const u160_state = (secret, identifier) => [
	u32_state(secret, identifier + '_5'),
	u32_toaltstack,
	u32_state(secret, identifier + '_4'),
	u32_toaltstack,
	u32_state(secret, identifier + '_3'),
	u32_toaltstack,
	u32_state(secret, identifier + '_2'),
	u32_toaltstack,
	u32_state(secret, identifier + '_1'),
	u32_fromaltstack,
	u32_fromaltstack,
	u32_fromaltstack,
	u32_fromaltstack 
].join('')


function hexStringTo32BitNumbers(hexString) {
  if (hexString.length !== 40) {
    throw new Error('Hex string must be 20 bytes (40 characters) long');
  }

  const numbers = [];
  for (let i = 0; i < hexString.length; i += 8) {
    // Extract 8 characters (4 bytes) at a time
    const substring = hexString.substring(i, i + 8);
    
    // Parse the substring as a hex number and add it to the result array
    const number = parseInt(substring, 16);
    numbers.push(number);
  }
  
  return numbers;
}


const u160_state_unlock = (secret, identifier, value) => 
	hexStringTo32BitNumbers(value)
	.reverse()
	.map((v,i) => u32_state_unlock(secret, identifier+`_${i+1}`, v) )
	.join('')