#include "net/tools/quic/abr.h"
#include "net/tools/quic/mpc.h"

MpcAbr::~MpcAbr() {
}

double MpcAbr::accept(Dispatcher &dispatcher, DP type, int value, const std::map<double, SSIMBasedQuality>& ssim_map) {
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

int MpcAbr::GetPause()
{
  return pause;
}

int MpcAbr::GetBuffer()
{
  return buffer_level_;
}

void MpcAbr::SetBuffer(int lvl) {
  buffer_level_ = lvl;
}


MpcAbr::MpcAbr(double segment_duration, double buffer_size,
               std::vector<double> bitrates)
    : buffer_level_(0.0),
      last_quality_(0),
      segment_duration_(segment_duration),
      bitrates_(bitrates),
      estimate_throughput_(0.0),
      estimate_error_(0.0)
{
      buffer_size_ = buffer_size;
      startup = true;
}

int MpcAbr::GetQuality(double throughput, double* pause)
{
  double best = 0.0;
  int quality = 0;
  double tput_e = throughput / (1.0 + estimate_error_);
  //std::cerr << "Search tput_e=" << tput_e << " bl=" << buffer_level_ << "/" << buffer_size_ << std::endl;
  for (unsigned q = 0; q < bitrates_.size(); ++q) {
    double v = Search(kSearchDepth, tput_e, buffer_level_, last_quality_, q);
    if (q == 0 || v > best) {
      best = v;
      quality = q;
    }
  }
  last_quality_ = quality;
  estimate_throughput_ = throughput;

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

const std::vector<AbrLogLine>& MpcAbr::GetLog()
{
  return log_;
}

double MpcAbr::Evaluate(int prev_quality, int quality, double rebuffer)
{
  const double lambda = 1.0;
  const double mu = 3.0;
  double score = bitrates_[quality];
  score -= lambda * fabs(bitrates_[quality] - bitrates_[prev_quality]);
  score -= mu * rebuffer;
  return score;
}

double MpcAbr::Search(int depth, double throughput, double buffer_level,
                      int prev_quality, int quality)
{
  if (buffer_level + segment_duration_ > buffer_size_) {
    buffer_level = buffer_size_ - segment_duration_;
  }
  double time = (bitrates_[quality] * segment_duration_) / throughput;
  double rebuffer = 0.0;
  buffer_level -= time;
  if (buffer_level < 0.0) {
    rebuffer += -buffer_level;
    buffer_level = 0.0;
  }
  buffer_level += segment_duration_;

  double value = Evaluate(prev_quality, quality, rebuffer);
  --depth;
  if (depth > 0) {
    double best = 0.0;
    for (unsigned q = 0; q < bitrates_.size(); ++q) {
      double v = Search(depth, throughput, buffer_level, quality, q);
      if (q == 0 || v > best) {
        best = v;
      }
    }
    value += best;
  }
  return value;
}

void MpcAbr::PreUpdate(double pause, uint32_t walltime, double segment_size) {

  // segment_size is in bytes
  double throughput = 8.0 * segment_size / walltime;
  double error = std::fabs(estimate_throughput_ - throughput) / throughput;
  //std::cout << estimate_throughput_ << " <-> " << throughput << " : " << error << std::endl;
  past_errors_.push_back(error);
  if (past_errors_.size() > kErrorWindow) {
    past_errors_.pop_front();
  }
  estimate_error_ = 0.0;
  for (auto error: past_errors_) {
    if (error > estimate_error_) {
      estimate_error_ = error;
      //std::cout << estimate_error_ << std::endl;
    }
  }

  if (buffer_level_ < 0.0) {
    std::cerr << (startup ? "[startup] " : "[rebuffer] ") << (int)(-buffer_level_) << std::endl;
    buffer_level_ = 0.0;
  }
  startup = false;

  buffer_level_ += segment_duration_;
}

void MpcAbr::PostUpdate(double pause, uint32_t walltime) {
  if (pause > 0.0) {
    std::cerr << "[pause] " << (int)(pause) << std::endl;
    buffer_level_ -= pause;
  }

  std::cerr << "[buffer] " << (int)(buffer_level_) << std::endl;
}

