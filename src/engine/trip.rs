use crate::engine::types::TripContext;

pub fn log_trip(ctx: &TripContext) {
    // canonical score trip log
    eprintln!(
        "TRIP(score) tgid={} comm={} score={:.2} distinct={} bytes={} enforce={}",
        ctx.tgid, ctx.comm, ctx.score, ctx.distinct, ctx.bytes, ctx.enforce
    );
}

pub fn log_trip_score_dir(ctx: &TripContext, dh: u64, dir_n: usize) {
    eprintln!(
        "TRIP(score) tgid={} comm={} score={:.2} distinct={} bytes={} enforce={} dh={} dir_n={}",
        ctx.tgid, ctx.comm, ctx.score, ctx.distinct, ctx.bytes, ctx.enforce, dh, dir_n
    );
}

pub fn log_trip_threshold(tgid: u32, comm: &str, distinct: usize, bytes: u64, enforce: bool) {
    eprintln!(
        "TRIP tgid={} comm={} distinct={} bytes={} enforce={}",
        tgid, comm, distinct, bytes, enforce
    );
}
