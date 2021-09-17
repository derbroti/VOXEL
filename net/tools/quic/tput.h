#ifndef TPUT_ABR
#define TPUT_ABR

#include <vector>
#include <iostream>
#include <cmath>

// time in ms
// size in bits
// bitrate in kbps (equivalent to bits/ms)

class BaseAbr;
class Dispatcher;

class ThroughputAbr: public BaseAbr {
 public:
  ~ThroughputAbr() override;
  ThroughputAbr(double segment_duration,
                double buffer_size,
                std::vector<double> bitrates);

  int GetQuality(double throughput, double* pause);
  int GetPause();
  int GetBuffer();
  void SetBuffer(int lvl);
  void PreUpdate(double pause, uint32_t);
  void PostUpdate(double pause, uint32_t);
  double accept(Dispatcher &dispatcher, DP type, int retry, const std::map<double, SSIMBasedQuality>& ssim_map) override;
  const std::vector<AbrLogLine>& GetLog();

  int pause;

  //private:
  double buffer_level_;
  double segment_duration_;
  std::vector<double> bitrates_;
  std::vector<AbrLogLine> log_;
  static constexpr double kSafetyFactor = 0.9;
  int QualityFromThroughput(double throughput);
};

#endif //TPUT_ABR
