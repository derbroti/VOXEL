#include "net/tools/quic/abr.h"
#include "net/tools/quic/tput.h"

ThroughputAbr::~ThroughputAbr() {
}

double ThroughputAbr::accept(Dispatcher &dispatcher, DP type, int value, const std::map<double, SSIMBasedQuality>& ssim_map) {
  switch (type) {
    case GQ:
      return dispatcher.GetQuality(*this, value);
    case GP:
      return dispatcher.GetPause(*this);
    case GB:
      return dispatcher.GetBuffer(*this);
    case SB:
      dispatcher.SetBuffer(*this, value);
      return 0.0;
  default: 
    std::cerr << "error requested method not available" << std::endl;
    exit(-1);
    return 0.0;
  }
}

ThroughputAbr::ThroughputAbr(double segment_duration,
                             double buffer_size,
                             std::vector<double> bitrates)
    : buffer_level_(0.0),
      segment_duration_(segment_duration),
      bitrates_(bitrates)
{
  buffer_size_ = buffer_size;
  startup = true;
}

int ThroughputAbr::GetPause()
{
  return pause;
}

int ThroughputAbr::GetBuffer()
{
  return buffer_level_;
}

void ThroughputAbr::SetBuffer(int lvl) {
  buffer_level_ = lvl;
}

int ThroughputAbr::GetQuality(double throughput, double* pause)
{
  int quality = QualityFromThroughput(throughput * kSafetyFactor);
  if (buffer_level_ + segment_duration_ > buffer_size_) {
    *pause = buffer_level_ + segment_duration_ - buffer_size_;
  } else {
    *pause = 0.0;
  }

  AbrLogLine log_line;
  if (log_.empty()) {
    log_line.playhead_time_ = -this->buffer_level_;
  } else {
    log_line.playhead_time_ = log_.back().playhead_time_ + segment_duration_ +
      log_.back().buffer_level_ - this->buffer_level_;
  }
  log_line.buffer_level_ = this->buffer_level_;
  log_line.throughput_ = throughput;
  log_line.quality_ = quality;
  log_line.bitrate_ = bitrates_[quality];
  log_line.pause_ = *pause;
  log_.push_back(log_line);

  this->pause = *pause;
  return quality;
}

const std::vector<AbrLogLine>& ThroughputAbr::GetLog() 
{
  return log_;
}

int ThroughputAbr::QualityFromThroughput(double throughput)
{
  for (size_t i = 1; i < bitrates_.size(); ++i) {
    if (bitrates_[i] > throughput) {
      return i - 1;
    }
  }
  return bitrates_.size() - 1;
}

void ThroughputAbr::PreUpdate(double pause, uint32_t walltime) {

  if (buffer_level_ < 0.0) {
    std::cerr << (startup ? "[startup] " : "[rebuffer] ") << (int)(-buffer_level_) << std::endl;
    buffer_level_ = 0.0;
  }
  startup = false;

  buffer_level_ += segment_duration_;
}

void ThroughputAbr::PostUpdate(double pause, uint32_t walltime) {
  if (pause > 0.0){
    std::cerr << "[pause] " << (int)(pause) << std::endl;
    buffer_level_ -= pause;
  }

  std::cerr << "[buffer] " << (int)(buffer_level_) << std::endl;
}
