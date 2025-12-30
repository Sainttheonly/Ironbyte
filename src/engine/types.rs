#[derive(Debug, Clone)]
pub struct TripContext<'a> {
    pub tgid: u32,
    pub comm: &'a str,
    pub score: f64,
    pub distinct: u32,
    pub bytes: u64,
    pub enforce: bool,
}
