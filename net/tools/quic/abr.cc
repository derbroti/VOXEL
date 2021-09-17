#include "net/tools/quic/abr.h"
#include "net/tools/quic/bola.h"
#include "net/tools/quic/tput.h"
#include "net/tools/quic/mpc.h"

//#define SLST_DEBUG

BaseAbr::~BaseAbr() {
}

int Dispatcher::GetPause(BolaAbr &bola) {
  return bola.pause;
}

int Dispatcher::GetPause(MpcAbr &mpc) {
  return mpc.pause;
}

int Dispatcher::GetPause(ThroughputAbr &tput) {
  return tput.pause;
}

int Dispatcher::GetBuffer(BolaAbr &bola) {
  return bola.GetBuffer();
}

int Dispatcher::GetBuffer(MpcAbr &mpc) {
  return mpc.GetBuffer();
}

int Dispatcher::GetBuffer(ThroughputAbr &tput) {
  return tput.GetBuffer();
}

void Dispatcher::SetBuffer(BolaAbr &bola, int lvl) {
  bola.SetBuffer(lvl);
}
void Dispatcher::SetBuffer(ThroughputAbr &tput, int lvl) {
  tput.SetBuffer(lvl);

}
void Dispatcher::SetBuffer(MpcAbr &mpc, int lvl){
  mpc.SetBuffer(lvl);
}


double Dispatcher::GetQuality(BolaAbr &bola, int retry, const std::map<double, SSIMBasedQuality>& ssim_map) {
  double pause = 0.0;

  double tp = transport_->AddThroughput();
  uint32_t time = transport_->GetTime(/*unrel=*/true);

  bola.PreUpdate(pause, time, retry);
  double ssim = bola.GetQuality(tp, &pause, retry, ssim_map);
  bola.PostUpdate(pause, time, retry);
  
  return ssim;
}

double Dispatcher::GetQuality(ThroughputAbr &tput, int retry) {
  double pause = 0.0;

  double tp = transport_->AddThroughput();
  uint32_t time = transport_->GetTime(/*unrel=*/true);

  tput.PreUpdate(pause, time);
  int q = tput.GetQuality(tp, &pause);
  tput.PostUpdate(pause, time);

  return (double)q;
}

double Dispatcher::GetQuality(MpcAbr &mpc, int retry) {
  double pause = 0.0;

  double tp = transport_->AddThroughput();
  uint32_t time = transport_->GetTime(/*unrel=*/true);
  double segment_size = transport_->GetSegmentSize(/*unrel=*/false) + transport_->GetSegmentSize(/*unrel=*/true);

  mpc.PreUpdate(pause, time, segment_size);
  int q = mpc.GetQuality(tp, &pause);
  mpc.PostUpdate(pause, time);

  return (double)q;
}


MovingAverage::MovingAverage()
    : throughput_slow_(0.0),
      throughput_fast_(0.0),
      cumulative_time_(0.0)
{
}

void MovingAverage::AddMeasurement(double throughput, double time)
{
  double alpha = std::pow(0.5, time / kHalfLifeSlow);
  throughput_slow_ = alpha * throughput_slow_ + (1.0 - alpha) * throughput;
  alpha = std::pow(0.5, time / kHalfLifeFast);
  throughput_fast_ = alpha * throughput_fast_ + (1.0 - alpha) * throughput;
  cumulative_time_ += time;
}

double MovingAverage::GetThroughput()
{
  if (cumulative_time_ <= 0.0) {
    return 0.0;
  }
  // zero factor avoids low estimates until average warms up
  double zero_factor = 1.0 - std::pow(0.5, cumulative_time_ / kHalfLifeSlow);
  double slow = throughput_slow_ / zero_factor;
  zero_factor = 1.0 - std::pow(0.5, cumulative_time_ / kHalfLifeFast);
  double fast = throughput_fast_ / zero_factor;
  return std::min(slow, fast);
}
