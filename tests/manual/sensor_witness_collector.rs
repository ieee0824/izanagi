//! Copy to examples/sensor_witness_collector.rs in the disposable Linux checkout.
use izanagi::{
    ebpf_tracer::EbpfTracer,
    event::SyscallCategory,
    tracer::{TraceFilter, Tracer},
};
use std::io::Write;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(args.len() == 4, "usage: collector OBJECT EVENTS STOP_FILE");
    let tracer = EbpfTracer::with_ebpf_obj_path(&args[1]);
    let filter = TraceFilter {
        categories: vec![
            SyscallCategory::File,
            SyscallCategory::Network,
            SyscallCategory::Process,
        ],
        pids: None,
    };
    let (mut legacy, mut telemetry) = tracer
        .start_observation(&filter, "sensor-witness-136".into())
        .await?;
    let drain = tokio::spawn(async move { while legacy.recv().await.is_some() {} });
    let mut output = std::io::BufWriter::new(std::fs::File::create(&args[2])?);
    println!("READY");
    std::io::stdout().flush()?;
    let result = async {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(90);
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            tokio::select! {
                event = telemetry.recv() => {
                    let event = event.ok_or_else(|| anyhow::anyhow!("telemetry closed"))?;
                    serde_json::to_writer(&mut output, &event)?;
                    writeln!(output)?;
                }
                _ = tick.tick() => {
                    output.flush()?;
                    if std::path::Path::new(&args[3]).exists() { break; }
                    anyhow::ensure!(tokio::time::Instant::now() < deadline, "collector deadline");
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let stopped = tracer.stop().await;
    drain.abort();
    output.flush()?;
    result?;
    stopped
}
