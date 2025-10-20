/// Compute MSM = [a]P + [b]Q
/// Binary decomposition of scalar 'a' is given by an addition-chain like a = a0 + 2.a1 + 4.a2 + ..
/// W-windowed decomposition of the same expression is given by a = a0 + 2^(w.1) a1 + 2 ^(w.2) a2 + ...
/// Therefore, point scalar multiplication [a]P can be expressed as:
/// [a]P = [a0]P + [a1] (2^w P) + [a2] (2^2w P) +..
/// Since P is a constant derived from verification key, the expression (2 ^ w.i P) can be baked into the Script
/// Same procedure is repeated separately for [b]Q and their results can be combined to yield the total MSM result
///
/// For our purposes we select w = 8 (WINDOW_G1_MSM), the scalar a is a 254-bit scalar element, as such we obtain 254/8 ~ 32 addition terms
/// Each of the w-bit doubling lookup table querying + addition with the accumulator consumes some script size k
/// We batch multiple such double+add Scripts inside a single chunk. For w = 8, BATCH_SIZE_PER_CHUNK = 8 where k * BATCH_SIZE_PER_CHUNK < 4M
///
/// As such a batch of double+addition terms is implemented on a chunk, thus a single point-scalar multiplication requires around 32/8 = 4 chunks
/// This number increases linearly as the number of scalar grows.
use super::fq2::Fq2;
use super::utils::{fq_to_bits, Hint};
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::{fr::Fr, g1::G1Affine};
use crate::treepp::*;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField};
use itertools::Itertools;
use num_bigint::BigUint;

// Function used to compile a single msm tapscript for unchunked verifier only
pub fn hinted_msm_with_constant_bases_affine(
    bases: &[ark_bn254::G1Affine],
    scalars: &[ark_bn254::Fr],
) -> (Script, Vec<Hint>) {
    println!("use hinted_msm_with_constant_bases_affine");
    assert_eq!(bases.len(), scalars.len());

    let all_rows = g1_multi_scalar_mul(bases.to_vec(), scalars.to_vec());
    let mut all_hints: Vec<Hint> = vec![];
    let mut prev = ark_bn254::G1Affine::identity();
    let mut scr = script!();

    let all_rows_len = all_rows.len();
    let num_scalars = scalars.len();
    let psm_len = all_rows.len() / num_scalars;

    for (idx, ((row_out, row_scr, row_hints), _)) in all_rows.into_iter().enumerate() {
        all_hints.extend_from_slice(&row_hints);

        let temp_scr = script! {
            // [hints, t, scalar]
            {G1Affine::push(prev)}
            {Fr::push(scalars[idx/psm_len] )} // fq0, fq1
            {row_scr}
            if idx == all_rows_len-1 { // save final output
                {Fq2::copy(0)}
                {Fq2::toaltstack()}
            }
            {G1Affine::push(row_out)}
            {G1Affine::equalverify()}
            {G1Affine::push(prev) }
            {G1Affine::equalverify()}
            if idx == all_rows_len-1 {
                {Fq2::fromaltstack()}
            }
        };

        scr = script! {
            {scr}
            {temp_scr}
        };
        prev = row_out;
    }

    (scr, all_hints)
}

pub const WINDOW_G1_MSM: u32 = 8;
pub const BATCH_SIZE_PER_CHUNK: u32 = 8;

// Core function generates lookup table
// A lookup table is a series of if-conditionals that take as input a w-bit scalar slice
pub(crate) fn dfs_with_constant_mul(
    index: u32,
    depth: u32,
    mask: u32,
    p_mul: &[ark_bn254::G1Affine],
) -> Script {
    if depth == 0 {
        return script! {
            OP_IF
                { G1Affine::push(p_mul[(mask + (1 << index)) as usize]) }
            OP_ELSE
                if mask == 0 {
                    { G1Affine::identity() }
                } else {
                    { G1Affine::push(p_mul[mask as usize]) }
                }
            OP_ENDIF
        };
    }
    script! {
        OP_IF
            { dfs_with_constant_mul(index + 1, depth - 1, mask + (1 << index), p_mul) }
        OP_ELSE
            { dfs_with_constant_mul(index + 1, depth - 1, mask, p_mul) }
        OP_ENDIF
    }
}

// Given a curve point 'q', the function generates separate lookup tables for each of the Fr::N_BITS(254)/window terms in addition chain
// Table for i-th term in addition-chain is for (2^(w.i) P).
// Each table contains 2^w rows formed by repeated doubling of (2^(w.i)P)
// This way [a_j] (2^(w.i)P) can be obtained by checking the a_j-the entry of this table,
// where a_j is a w-bit scalar slice i.e. a_j \in [0..2^w -1]

// This function returns N-Tables each pairing with an addition term
// Output includes an array of tables-entries and an array of precomputed table scripts.
fn generate_lookup_tables(
    q: ark_bn254::G1Affine,
    window: usize,
) -> (Vec<Vec<ark_bn254::G1Affine>>, Vec<Script>) {
    let num_tables = (Fr::N_BITS as usize).div_ceil(window);

    let mut all_tables_scr = vec![];
    let mut all_tables = vec![];

    for i in 0..num_tables {
        let doubling_factor = BigUint::one() << (i * window); // (2^(w.i))
        let doubled_base = (q * ark_bn254::Fr::from(doubling_factor)).into_affine(); // (2^(w.i) P)

        let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
        p_mul.push(ark_bn254::G1Affine::zero()); // [a_0] (2^(w.i) P)
        for _ in 1..(1 << window) {
            let entry = (*p_mul.last().unwrap() + doubled_base).into_affine(); // [a_i] (2^(w.i) P)
            p_mul.push(entry);
        }

        let p_mul_scr = { dfs_with_constant_mul(0, window as u32 - 1, 0, &p_mul) };
        all_tables_scr.push(p_mul_scr);
        all_tables.push(p_mul);
    }
    (all_tables, all_tables_scr)
}

// This function computes the slice (w-bit segment) of scalar that is used as an index to
// the corresponding row of a table.
// The index of slice of scalar i.e {a_i} and the index of tables (chunks) i.e {(2^2wi P)} match
// Output is a value and a script to generate that value from a scalar
fn get_query_for_table_index(
    scalar: ark_bn254::Fr,
    window: usize,
    table_index: usize,
) -> (u32, Script) {
    let num_tables: u32 = Fr::N_BITS.div_ceil(window as u32);
    // Split Scalar into bits and group window size
    let chunks = fq_to_bits(scalar.into_bigint(), window); // {a_0, ..,a_N}
                                                           // Get Scalar slice (w-bit segment) at index position i.e. a_i
    let elem = chunks[table_index];
    let size = num_tables * window as u32;
    let scr = script! {
        // [scalar]
        {Fr::convert_to_le_bits_toaltstack()}
        // [254-bits]
        for _ in Fr::N_BITS..size {
            {0}
        }
        // [W*NUM_TABLES-bits]
        for _ in 0..Fr::N_BITS {
            OP_FROMALTSTACK
        }
        for i in 0..size {
            if i/window as u32 == (table_index as u32) {
                OP_TOALTSTACK // preserve all bits for the corresponding table-index
            } else {
                OP_DROP
            }
        }
        for _ in 0..window {
            OP_FROMALTSTACK
        }
        // w-bit value a_i
    };
    (elem, scr)
}

// Given a precomputed table of some table index
// Lookup a_i-th row and return result
// The result is a G1Affine element corresponding to [a_i] (2^(w.i) P)
fn query_table(
    table: (Vec<ark_bn254::G1Affine>, Script),
    row_index: (usize, Script),
) -> (ark_bn254::G1Affine, Script) {
    let row = table.0[row_index.0];
    let scr = script! {
        // [scalar]
        {row_index.1}
        // [scalar slice] => a_i
        {table.1}
        // [a_i] (2 ^ (w.i) P)
    };
    (row, scr)
}

/// Compute: Sum of [a_i] (2^ (wi) P) for i = 0..N, N is the number of terms in addition chain
/// BATCH_SIZE_PER_CHUNK such terms are batached inside a chunk
/// init_acc is the starting value of the accumulator; for chained point-scalar multiplication it is the output of previous point scalar mul
/// Output is an array of (value, script, hints) required for execution of each of the chunks
fn accumulate_addition_chain_for_a_scalar_mul(
    init_acc: ark_bn254::G1Affine,
    base: ark_bn254::G1Affine,
    scalar: ark_bn254::Fr,
    window: usize,
) -> Vec<(ark_bn254::G1Affine, Script, Vec<Hint>)> {
    let mut all_tables_result: Vec<(ark_bn254::G1Affine, Script, Vec<Hint>)> = vec![];

    let num_tables = (Fr::N_BITS as usize).div_ceil(window);
    let tables = generate_lookup_tables(base, window);

    let mut prev = init_acc;

    for batched_table_indices in &(0..num_tables).chunks(BATCH_SIZE_PER_CHUNK as usize) {
        let mut vec_row_g1_scr = Vec::new();
        let mut vec_add_scr = Vec::new();
        let mut vec_add_hints = Vec::new();

        for table_index in batched_table_indices {
            let (scalar_slice, scalar_slice_script) =
                get_query_for_table_index(scalar, window, table_index);
            let (selected_table_vec, selected_table_script) =
                (tables.0[table_index].clone(), tables.1[table_index].clone());
            let (row_g1, row_g1_scr) = query_table(
                (selected_table_vec, selected_table_script),
                (scalar_slice as usize, scalar_slice_script),
            );

            // accumulate value using hinted_check_add
            let (add_scr, add_hints) = G1Affine::hinted_check_add(prev, row_g1);

            prev = (prev + row_g1).into_affine(); // output of this chunk: t + q
            vec_row_g1_scr.push(row_g1_scr);
            vec_add_scr.push(add_scr);
            vec_add_hints.extend(add_hints);
        }

        let n = vec_row_g1_scr.len();

        let scr = script! {
            // [hints, t, scalar]
            {Fq2::copy(1)} {Fq2::toaltstack()}
            // [hints, t, scalar] [t]

            for i in 0..n {
                // [hints, t, scalar]
                {Fr::copy(0)} {Fr::toaltstack()}
                // [hints, t, scalar] [t, scalar]
                {vec_row_g1_scr[i].clone()}
                // [hints, t, q] where q = row_g1 =  [scalar_slice] (2^(w*table_index) base)
                {vec_add_scr[i].clone()}
                // [hints, t+q]
                {Fr::fromaltstack()}
                // [hints, t+q, scalar]
            }
            // [t+q, scalar] [t]
            {Fr::drop()}
            {Fq2::fromaltstack()}
            {Fq2::roll(2)}
            // [t, t+q]
        };

        all_tables_result.push((prev, scr, vec_add_hints)); // (output_of_chunk, Script_of_chunk, Hints_for_chunk)
    }

    // output for all tables
    all_tables_result
}

// This function wraps over multiple point scalar multiplications to form a single MSM
// result of one point-scalar mul is passed as initial value for the next chain of point-scalar mul
pub(crate) fn g1_multi_scalar_mul(
    bases: Vec<ark_bn254::G1Affine>,
    scalars: Vec<ark_bn254::Fr>,
) -> Vec<((ark_bn254::G1Affine, Script, Vec<Hint>), usize)> {
    assert_eq!(bases.len(), scalars.len());
    let mut prev = ark_bn254::G1Affine::identity();
    let window = WINDOW_G1_MSM as usize;
    let mut aggregate_result_of_all_scalar_muls = vec![];

    for i in 0..bases.len() {
        let scalar_mul_res =
            accumulate_addition_chain_for_a_scalar_mul(prev, bases[i], scalars[i], window);
        prev = scalar_mul_res[scalar_mul_res.len() - 1].0;
        for x in scalar_mul_res {
            aggregate_result_of_all_scalar_muls.push((x, i));
        }
    }
    aggregate_result_of_all_scalar_muls
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::g1::G1Affine;
    use crate::execute_script_without_stack_limit;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_get_query_for_table_index() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        for _ in 0..5 {
            let fq = ark_bn254::Fr::rand(&mut prng);
            let window = (u32::rand(&mut prng) % WINDOW_G1_MSM) + 1;
            let num_tables: u32 = Fr::N_BITS.div_ceil(window);
            let random_index = u32::rand(&mut prng) % num_tables;
            let (value, slice_scr) =
                get_query_for_table_index(fq, window as usize, random_index as usize);

            let scr = script! {
                {Fr::push(fq)}
                {slice_scr}
                for _ in 0..window {
                    OP_TOALTSTACK
                }
                // sum up bits to tally with value
                {0}
                for i in 0..window {
                    OP_FROMALTSTACK
                    OP_ADD
                    if i != window-1 {
                        OP_DUP
                        OP_ADD
                    }
                }
                {value}
                OP_EQUAL OP_VERIFY
                OP_TRUE
            };
            let res = execute_script(scr);
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            assert!(res.success);
            assert!(res.final_stack.len() == 1);
        }
    }

    #[test]
    fn test_query_table() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let window = WINDOW_G1_MSM as usize;
        let tables = generate_lookup_tables(q, window);
        let num_tables = tables.1.len();
        let table_index = u32::rand(&mut prng) % num_tables as u32;

        let fq = ark_bn254::Fr::rand(&mut prng);

        let (value, slice_scr) = get_query_for_table_index(fq, window, table_index as usize);

        let selected_table = (
            tables.0[table_index as usize].clone(),
            tables.1[table_index as usize].clone(),
        );
        let (row, row_scr) = query_table(selected_table, (value as usize, slice_scr));

        let tap_len = row_scr.len();
        let scr = script! {
            {Fr::push(fq)}
            {row_scr}
            {G1Affine::push(row)}
            {G1Affine::equalverify()}
            OP_TRUE
        };

        let res = execute_script(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(res.success);
        assert!(res.final_stack.len() == 1);
        println!(
            "tap len {} stack len {}",
            tap_len, res.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_hinted_msm_with_constant_bases_affine_script() {
        let n = 2;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let expect = ark_bn254::G1Projective::msm(&bases, &scalars).unwrap();
        let expect = expect.into_affine();
        let (msm, hints) = hinted_msm_with_constant_bases_affine(&bases, &scalars);

        let start = start_timer!(|| "collect_script");
        println!("hints {:?}", hints.len());
        let tap_len = msm.len();
        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { msm }

            { G1Affine::push(expect) }
            { G1Affine::equalverify() }
            OP_TRUE
        };
        end_timer!(start);

        println!("hinted_msm_with_constant_bases: = {} bytes", tap_len);
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script_without_stack_limit(script);
        if exec_result.final_stack.len() > 1 {
            for i in 0..exec_result.final_stack.len() {
                println!("{i:} {:?}", exec_result.final_stack.get(i));
            }
        }
        end_timer!(start);
        assert!(exec_result.success);
    }

    #[test]
    fn test_accumulate_rows() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let fq = ark_bn254::Fr::rand(&mut prng);
        let window = WINDOW_G1_MSM as usize;
        let mut prev = ark_bn254::G1Affine::identity();
        let all_rows = accumulate_addition_chain_for_a_scalar_mul(prev, q, fq, window);

        let expected_msm = (q * fq).into_affine();
        let calculated_msm = all_rows[all_rows.len() - 1].0;
        assert_eq!(expected_msm, calculated_msm);

        for (row_out, row_scr, row_hints) in all_rows {
            let tap_len = row_scr.len();
            let scr = script! {
                // [hints, t, scalar]
                for h in &row_hints {
                    {h.push()}
                }
                {G1Affine::push(prev)}
                {Fr::push(fq)}
                {row_scr}
                {G1Affine::push(row_out)}
                {G1Affine::equalverify()}
                {G1Affine::push(prev) }
                {G1Affine::equalverify()}
                OP_TRUE
            };

            let res = execute_script(scr);
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            prev = row_out;
            assert!(res.success);
            println!(
                "accumulate_addition_terms {:?} max_stat {:?}",
                tap_len, res.stats.max_nb_stack_items
            );
        }
    }

    #[test]
    fn test_accumulate_multiple_rows() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q0 = ark_bn254::G1Affine::rand(&mut prng);
        let fq0 = ark_bn254::Fr::rand(&mut prng);
        let q1 = ark_bn254::G1Affine::rand(&mut prng);
        let fq1 = ark_bn254::Fr::rand(&mut prng);
        let bases = vec![q0, q1];
        let scalars = vec![fq0, fq1];

        let num_scalars = scalars.len();
        let all_rows = g1_multi_scalar_mul(bases, scalars.clone());
        let psm_len = all_rows.len() / num_scalars;

        let expected_msm = (q0 * fq0 + q1 * fq1).into_affine();
        let calculated_msm = all_rows[all_rows.len() - 1].0 .0;
        assert_eq!(expected_msm, calculated_msm);

        let mut prev = ark_bn254::G1Affine::identity();
        for (idx, ((row_out, row_scr, row_hints), _)) in all_rows.into_iter().enumerate() {
            let scr = script! {
                // [hints, t, scalar]
                for h in &row_hints {
                    {h.push()}
                }
                {G1Affine::push(prev)}
                {Fr::push(scalars[idx/psm_len] )} // fq0, fq1
                {row_scr}
                {G1Affine::push(row_out)}
                {G1Affine::equalverify()}
                {G1Affine::push(prev) }
                {G1Affine::equalverify()}
                OP_TRUE
            };
            let res = execute_script(scr);
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            prev = row_out;

            assert!(res.success);
        }
    }
}
