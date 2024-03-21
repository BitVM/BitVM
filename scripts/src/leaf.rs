use bitcoin::ScriptBuf as Script;

pub struct Leaf<Model> {
    pub lock: fn(Model) -> Script,
    pub unlock: fn(Model) -> Script,
}

pub type LeafType<Model> = fn(Model) -> Leaf<Model>;

pub type Leaves<Model> = Vec<Leaf<Model>>;

pub fn is_leaf_executable<Model>(_leaf: Leaf<Model>, _model: Model) -> bool {
    true
}
