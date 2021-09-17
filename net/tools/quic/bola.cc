#include <cassert>

#include "net/tools/quic/abr.h"
#include "net/tools/quic/bola.h"

const bool kVerbose = false;

BolaAbr::~BolaAbr() {

}

double BolaAbr::accept(Dispatcher &dispatcher, DP type, int value, const std::map<double, SSIMBasedQuality>& ssim_map) {
  switch (type) {
    case GQ:
      return dispatcher.GetQuality(*this, value, ssim_map);
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

BolaAbr::BolaAbr(double segment_duration,
                 double buffer_size,
                 std::vector<double> bitrates,
                 std::vector<double> ssims)
    : buffer_level_(0.0),
      last_quality_(-1),
      placeholder_(0.0),
      segment_duration_(segment_duration),
      bitrates_(bitrates),
      utilities_(bitrates.size()),
      average_ssim_(ssims)
{
  buffer_size_ = buffer_size;
  startup = true;

  // We should not recalculate utility array per segment.
  // When we need particular utilities, they are passed as parameters,
  // but the class averages are not changed.
  if (average_ssim_.empty()) {
    for (size_t i = 0; i < bitrates_.size(); ++i) {
      utilities_[i] = std::log(bitrates_[i] / bitrates_[0]);
    }
  } else {
    utilities_ = average_ssim_;
  }

  double alpha = (bitrates_[0] * utilities_[1] - bitrates_[1] * utilities_[0])
      / (bitrates_[1] - bitrates_[0]);
  std::cerr << "alpha:" << alpha << std::endl;
  double buffer_target = buffer_size_ - segment_duration_;

  // BolaE: We might need buffer expansion technique
  double minimum_target = kBufferLow + kMinThreshold * bitrates_.size();
  if (buffer_target < minimum_target) {
    buffer_target = minimum_target;
  }

  // Note that vp_ and gp_ should not be changed mid-session.
  vp_ = (buffer_target - kBufferLow) / (utilities_.back() + alpha);
  gp_ = (utilities_.back() * kBufferLow + alpha * buffer_target)
      / (buffer_target - kBufferLow);
  if (kVerbose) {
    std::cerr << "BOLA:" << std::endl;
    std::cerr << "Vp: " << vp_ << ", gp: " << gp_ << std::endl;

    for (size_t i = 0; i < bitrates_.size(); ++i) {
      std::cerr << i << "    " << i << "/-: " << BufferLevelForZeroScore(utilities_[i]);
      if (i > 0) {
        std::cerr << "    " << i << "/" << (i - 1) << ": "
                  << MinBufferLevelForQuality(i);
      }
      std::cerr << std::endl;
      if (false) {
        for (double j = 0.0; j < 32500; j += 4000) {
          std::cerr << j << " "
                    << ((vp_ * (utilities_[i] + gp_) - j) / bitrates_[i])
                    << std::endl;
        }
      }
    }
  }
}

int BolaAbr::GetPause()
{
	return pause;
}

int BolaAbr::GetBuffer()
{
	return buffer_level_;
}

void BolaAbr::SetBuffer(int lvl) {
  buffer_level_ = lvl;
}

/*
int BolaAbr::GetQuality(double throughput, double* pause, int retry, const std::vector<double> &segment_sizes_bits)
{
  int quality = BolaE(this->buffer_level_, throughput, segment_sizes_bits, pause, retry);

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
*/

double BolaAbr::GetQuality(double throughput, double* pause, int retry, const std::map<double, SSIMBasedQuality>& ssim_map)
{
  double ssim = BolaE(this->buffer_level_, throughput, ssim_map, pause, retry, kNewDownload);
  int quality = ssim_map.at(ssim).quality;

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

  return ssim;
}

const std::vector<AbrLogLine>& BolaAbr::GetLog()
{
  return log_;
}

int BolaAbr::BolaE(double buffer_level, double throughput,
                   double* pause, int retry,
                   const DownloadProgress& progress)
{
  std::vector<double> empty_sizes;
  return BolaE(buffer_level, throughput, empty_sizes, pause, retry, progress);
}

int BolaAbr::BolaE(double buffer_level, double throughput,
                   const std::vector<double> &sizes_bits,
                   double* pause, int retry,
                   const DownloadProgress& progress)
{
  std::map<double, SSIMBasedQuality> ssim_map;
  for (unsigned q = 0; q < utilities_.size(); ++q) {
    double ssim = utilities_[q];

    // hack to make sure no duplicate ssim - should always be false
    while (ssim_map.find(ssim) != ssim_map.end()) {
      ssim += 0.000000001;
    }

    double bits = 0.0;
    if (sizes_bits.empty()) {
      bits = bitrates_[q] * segment_duration_;
    } else {
      bits = sizes_bits[q];
    }

    SSIMBasedQuality sq;
    sq.size = bits / 8.0; // casted to size_t
    sq.quality = q;
    sq.required_frames = 100; // placeholder with no effect

    ssim_map[ssim] = sq;
  }

  double ssim = BolaE(buffer_level, throughput, ssim_map, pause, retry, progress);
  return ssim_map[ssim].quality;
}

double BolaAbr::BolaE(double buffer_level, double throughput,
                      const std::map<double, SSIMBasedQuality>& ssim_map_par,
                      double* pause, int retry,
                      const DownloadProgress& progress)
{
  std::map<double, SSIMBasedQuality> ssim_map_copy;
  if (progress.in_progress) {
    //                                                      _         _
    // TODO: not the most efficient way, but works for now   \_(-_-)_/
    ssim_map_copy = ssim_map_par;
    for (auto ssim_entry : ssim_map_copy) {
      if (ssim_entry.second.quality == progress.quality) {
        //std::cerr << "pre:" << ssim_entry.second.size;
        if (ssim_entry.first >= progress.ssim) {
          // By not adjusting size when ssim_entry.first < progress.ssim,
          // we avoid being too eager to abort all downloads before intended.
          // Without this check, quitting might show a remaining size very
          // close to zero, which brings the denominator in the Score()
          // function very close to zero. Thus, we are tempted to always quit.
          if (!progress.reliable) {
            ssim_entry.second.size -= ssim_entry.second.reliable_size;
          }
          //std::cerr << " post:" << ssim_entry.second.size << " exp:" << progress.size << std::endl;
          //assert(ssim_entry.second.size == progress.size);
          // We can have already downloaded the entire part that is required for some SSIMS.
          if (progress.downloaded >= ssim_entry.second.size) {
            ssim_entry.second.size = 1;
          } else {
            ssim_entry.second.size -= progress.downloaded;
          }
        }
      }
    }
  }
  const std::map<double, SSIMBasedQuality>& ssim_map =
      (progress.in_progress ? ssim_map_copy : ssim_map_par);

  int quality = 0;
  double ssim = 0.0;
  *pause = 0.0;

  // Use empty_sizes get long-term quality from throughput
  std::vector<double> empty_sizes;

  if (last_quality_ == -1) {
    // Initialization
    assert(!progress.in_progress);
    ibr_safety_factor_ = 1.0;
    if (buffer_size_ > segment_duration_) {
      ibr_safety_factor_target_ = segment_duration_ /
          (buffer_size_ - segment_duration_);
      if (ibr_safety_factor_target_ < kIbrSafetyFactor) {
        ibr_safety_factor_target_ = kIbrSafetyFactor;
      } else if (ibr_safety_factor_target_ > kSafetyFactor) {
        ibr_safety_factor_target_ = kSafetyFactor;
      }
    } else {
      // Should not arrive here, it is recommended that:
      // buffer_size_ >= 2.0 * segment_duration_
      ibr_safety_factor_target_ = kSafetyFactor;
    }
    // Get long term estimate for initial placeholder_ calculation:
    quality = QualityFromThroughput(kSafetyFactor * throughput, empty_sizes);
    placeholder_ = MinBufferLevelForQuality(quality);
    last_quality_ = quality;
    for(auto it = ssim_map.rbegin(); it != ssim_map.rend(); it++) {
      if (it->second.quality == quality) {
        return it->first;
      }
    }
    std::cerr << "ERROR: Failed to find quality level in ssim_map?\n";
    exit(1);
  }


  // We want to find a max_quality to reduce oscillations. We do this in two
  // steps.

  // 1. We first find a sustainable quality level. Note that we are using the
  // average over the whole video, that is bitrates_, as opposed to the sizes
  // seen in ssim_map. This is because we want sustainability in the "long"
  // term and not just for this segment.
  //
  // We will find the lowest bitrate that is larger than the throughput. Note
  // that this does not look sustainable, but the only downside is maybe
  // oscillations between adjacent quality levels. (Think BOLA-U as opposed to
  // BOLA-O.) This mechanism is meant to avoid oscillations and not to avoid
  // rebuffering; rebuffering is handled by other mechanisms. Also, by
  // allowing somewhat agressive switching up, we allow BOLA to exploit
  // the partial download options.
  int max_quality = 0;
  while (max_quality < (int)bitrates_.size() &&
         throughput <= bitrates_[max_quality]) {
    ++max_quality;
  }
  // Note that to revert to "BOLA-O" behavior, we can uncomment the following
  // lines.
  // if (max_quality > 0 && throughput < bitrates_.back()) {
  //   // Avoid choosing negative quality or missing on maximum bitrate.
  //   --max_quality;
  // }

  // 2. Now we want to relax the quality limit to the last_quality_. The idea
  // is that we're not increasing oscillations if we were already at a
  // higher quality.
  if (last_quality_ > max_quality) {
    max_quality = last_quality_;
  }

  // We will favor qualities <= last_quality_. Thus, BOLA will be inclined to
  // not drop in quality level even if SSIM for lower bitrates are almost
  // equal to current bitrate.
  ssim = QualityFromBufferLevel(buffer_level + placeholder_, ssim_map,
                                max_quality, /*favor_quality*/ last_quality_);
  quality = ssim_map.at(ssim).quality;

  /*
  if (ssim_map.size() == bitrates_.size()) {
    // If we have exactly one ssim_map entry per quality,
    // then we want to keep using BolaE oscillation avoidance.
    // If we have more than one ssim_map entry per quality,
    // then we do not use the oscillation avoidance algorithm.


    // Do not use sizes_bits to calculate sustainable_quality because
    // it is a long-term sustainability estimate.
    double sustainable_ssim = QualityFromThroughput(throughput, ssim_map);
    int sustainable_quality = ssim_map.at(sustainable_ssim).quality;
    // TODO: might create some oscillations if buffer_level_
    //       is not larger than 2 * segment_duration_

    //std::cout << "q=" << quality << " safe=" << safe_quality << " sustainable="
    //          << sustainable_quality << std::endl;

    if (quality > last_quality_ && quality > sustainable_quality) {
      if (sustainable_quality < last_quality_) {
        quality = last_quality_;
        bool found = false;
        for (auto it = ssim_map.begin(); it != ssim_map.end(); it++) {
          if (it->second.quality == quality) {
            ssim = it->first;
            found = true;
            break;
          }
        }
        if (!found) {
          std::cerr << "ERROR: Failed to find quality in ssim_map." << std::endl;
          exit(1);
        }
        //std::cout << "q=last=" << quality << std::endl;
      } else {
        quality = sustainable_quality;
        ssim = sustainable_ssim;
        //std::cout << "q=sustainable=" << quality << std::endl;
      }
    }
  }
  */

  // We replace InsufficientBufferRule with SafeDownloadSizeBits.
  // Note that if there is exactly one ssim_map entry per quality, this behaves exactly like InsufficientBufferRule.
  // First, we find the maximum buffer level:
  double safety_buffer_level = buffer_level;
  if (safety_buffer_level > buffer_size_ - segment_duration_) {
    safety_buffer_level = buffer_size_ - segment_duration_;
  }
  size_t safe_size_bytes = SafeDownloadSizeBits(safety_buffer_level, throughput)
      / 8.0;
  auto iter = ssim_map.find(ssim);
  size_t cur_size = iter->second.size;
  while (iter != ssim_map.begin() && cur_size > safe_size_bytes) {
    --iter;
    size_t new_size = iter->second.size;
    if (new_size < cur_size) {
      ssim = iter->first;
      quality = iter->second.quality;
      cur_size = new_size;
    }
  }

  if (!progress.in_progress) {

    ibr_safety_factor_ *= kSafetyFactor;
    if (ibr_safety_factor_ < ibr_safety_factor_target_) {
      ibr_safety_factor_ = ibr_safety_factor_target_;
    }
    // Update state

    // Check that the buffer is not too full.
    // Mainly, this is a mechanism to shrink the placeholder.
    // However, it also helps avoid filling the buffer with poor-quality video.
    // Note that we do not use the chosen ssim value but the average SSIM value
    // for the corresponding quality, also without calculating for segments
    // with missing frames. This makes the algorithm less aggressive with the
    // pausing and thus improves stability. It also avoids cases where the
    // chosen ssim value is so low (even lower than utilities_[0]) that
    // a negative buffer level is indicated.
    //double level = BufferLevelForZeroScore(std::max(utilities_[quality], ssim));
    double level = BufferLevelForZeroScore(ssim);
    if (level < kBufferLow) {
      // Add a safety mechanism to avoid depleting too much buffer.
      // We should not arrive here, but if we do, we need to adjust.
        std::cerr << "Error: Trying to drop buffer level to " << level
                  << " ms, dropping to " << kBufferLow << " ms instead."
                  << std::endl;
      level = kBufferLow;
    }
    if (buffer_level + placeholder_ > level) {
      placeholder_ = level - buffer_level;
      if (placeholder_ < 0.0) {
        *pause = -placeholder_;
        placeholder_ = 0.0;
      }
    }

    double overrun = buffer_level_ - *pause + segment_duration_ - buffer_size_;
    if (overrun > 0.0) {
      placeholder_ += overrun;
      *pause += overrun;
    }

    last_quality_ = quality;
  }

  return ssim;
}

double BolaAbr::Score(double buffer_level, double size_bits, double util)
{
  return (vp_ * (util + gp_) - buffer_level) / size_bits;
}

double BolaAbr::BufferLevelForZeroScore(double utility)
{
  return vp_ * (utility + gp_);
}

double BolaAbr::MinBufferLevelForQuality(int quality)
{
  if (quality == 0) {
    return 0.0;
  }
  // Note that this is a long term (as opposed to a particular segment)
  // calculation, so we use utilities_ as opposed to the current SSIM.
  double a = (bitrates_[quality - 1] * utilities_[quality] -
              bitrates_[quality] * utilities_[quality - 1])
      / (bitrates_[quality] - bitrates_[quality - 1]);
  return vp_ * (gp_ - a);
}

double BolaAbr::QualityFromBufferLevel(double buffer_level,
                                       const std::map<double, SSIMBasedQuality>& ssim_map,
                                       int max_quality, int favor_quality)
{
  // We will give an extra penalty in ssim to all qualities < favor_quality.
  // The penalty is the average drop in utility between qualities.
  double favor_ssim_penalty = ((utilities_.back() - utilities_.front()) /
                               (utilities_.size() - 1));
  double best_ssim = 0.0;
  double score = 0.0;
  for (auto ssim_entry: ssim_map) {
    int quality = ssim_entry.second.quality;
    /*if (quality > max_quality) {
      continue;
    }*/
    double ssim = ssim_entry.first;
    double effective_ssim = ssim;
    if (quality < favor_quality) {
      effective_ssim -= favor_ssim_penalty;
    }
    double size_bits = ssim_entry.second.size * 8.0;
    double s = Score(buffer_level, size_bits, effective_ssim);
    if (best_ssim == 0.0 || s > score) {
      score = s;
      best_ssim = ssim;
    }
  }
  return best_ssim;
}

int BolaAbr::QualityFromThroughput(double throughput,
                                   const std::vector<double> &sizes_bits)
{
  for (size_t i = 1; i < bitrates_.size(); ++i) {
    double rate = 0.0;
    if (sizes_bits.empty()) {
      rate = bitrates_[i];
    } else {
      rate = sizes_bits.at(i) / segment_duration_;
    }

    if (rate > throughput) {
      return i - 1;
    }
  }
  return bitrates_.size() - 1;
}

double BolaAbr::QualityFromThroughput(double throughput,
                                      const std::map<double, SSIMBasedQuality>& ssim_map)
{
  double ssim = 0.0;
  double min_rate = 0.0;
  for (auto iter = ssim_map.rbegin(); iter != ssim_map.rend(); iter++) {
    double rate = (8.0 * iter->second.size) / segment_duration_;
    if (rate <= throughput) {
      // we're done because we found the best ssim with rate <= throughput
      return iter->first;
    }
    if (min_rate == 0.0 || rate < min_rate) {
      ssim = iter->first;
      min_rate = rate;
    }
  }
  // we did not find a small enough option, use lowest bitrate available
  return ssim;
}

double BolaAbr::SafeDownloadSizeBits(double buffer_level, double throughput)
{
  return throughput * ibr_safety_factor_ * buffer_level;
}

int BolaAbr::InsufficientBufferRule(double buffer_level, double throughput,
                                    const std::vector<double> &sizes_bits)
{
  // If we have ssim_map, then we use SafeDownloadSizeBits() directly.
  // We only use InsufficientBufferRule when not using ssim_map.

  //std::cout << "IBR(bl=" << buffer_level << ", tp=" << throughput << ") : "
  //          << (throughput * ibr_safety_factor_ * buffer_level /
  //              segment_duration_) << std::endl;

  double safe_size = SafeDownloadSizeBits(buffer_level, throughput);
  for (size_t i = 1; i < bitrates_.size(); ++i) {
    double cur_size = 0.0;
    if (sizes_bits.empty()) {
      cur_size = bitrates_[i] * segment_duration_;
    } else {
      cur_size = sizes_bits.at(i);
    }
    if (cur_size > safe_size) {
      return i - 1;
    }
  }
  return bitrates_.size() - 1;
}


void BolaAbr::PreUpdate(double pause, uint32_t walltime, int retry) {

  if (buffer_level_ < 0.0) {
    if (buffer_level_ < -100000) {
      std::cerr << "rebuffer of more than 100s - not supposed to happen - stopping!" << std::endl;
      exit(-4);
    }
    std::cerr << (startup ? "[startup] " : "[rebuffer] ") << (int)(-buffer_level_) << std::endl;
    buffer_level_ = 0.0;
  }
  startup = false;

  if (!retry)
    buffer_level_ += segment_duration_;
}

void BolaAbr::PostUpdate(double pause, uint32_t walltime, int retry) {
  if (pause > 0.0 && !retry) {
    std::cerr << "[pause] " << (int)(pause) << std::endl;
    buffer_level_ -= pause;
  }

  std::cerr << "[" << (retry ? "retry-" : "") << "buffer] " << (int)(buffer_level_) << std::endl;
  std::cerr << "[placeholder] " << (int)(placeholder_) << std::endl;
}

BPPMovingAverage::BPPMovingAverage()
    : throughput_(0.0),
      cumulative_time_(0.0),
      cumulative_size_(0),
      warmed_up_1_(false),
      warmed_up_2_(false)
{
}

void BPPMovingAverage::AddMeasurement(size_t received_bytes, double time)
{
  double time_diff = time - cumulative_time_;
  size_t size_diff = received_bytes - cumulative_size_;
  double throughput = (double) (size_diff * 8) / time_diff;
  if (!warmed_up_1_ && throughput == 0) {
    warmed_up_1_ = true;
    return;
  }
  warmed_up_1_ = true;
  if (time_diff < 0) {
    std::cerr << "WARNING ILLEGAL TIME TRAVEL DETECTED!\n";
    return;
  }
  double throughput_pre = throughput_;
  throughput_ = alpha * throughput_ + (1.0 - alpha) * throughput;
  if (!warmed_up_2_) {
    throughput_ = throughput;
    warmed_up_2_ = true;
  }
  cumulative_time_ = time;
  cumulative_size_ = received_bytes;
  std::cerr << "tp:" << throughput << " t:" << time_diff << " tpp:" << throughput_pre << " tpa:" << throughput_ << std::endl;
}

double BPPMovingAverage::GetThroughput()
{
  if (cumulative_time_ <= 0.0) {
    return 0.0;
  }
  // zero factor avoids low estimates until average warms up
  double zero_factor = 1.0 - std::pow(0.5, cumulative_time_ / kHalfLife);
  return throughput_ / zero_factor;
}
