#ifndef MPC_ABR
#define MPC_ABR

#include <vector>
#include <list>
#include <iostream>
#include <cmath>

// time in ms
// size in bits
// bitrate in kbps (equivalent to bits/ms)

class BaseAbr;
class Dispatcher;

class MpcAbr: public BaseAbr {
 public:
  ~MpcAbr() override;
  MpcAbr(double segment_duration,
         double buffer_size,
         std::vector<double> bitrates);

  int GetQuality(double throughput, double* pause);
  int GetPause();
  int GetBuffer();
  void SetBuffer(int lvl);
  void PreUpdate(double pause, uint32_t walltime, double segment_size);
  void PostUpdate(double pause, uint32_t walltime);
  double accept(Dispatcher &dispatcher, DP type, int retry, const std::map<double, SSIMBasedQuality>& ssim_maps) override;
  const std::vector<AbrLogLine>& GetLog();

  int pause;

  //private:
  double buffer_level_;
  int last_quality_;
  double segment_duration_;
  std::vector<double> bitrates_;
  std::vector<AbrLogLine> log_;
  double estimate_throughput_;
  double estimate_error_;
  std::list<double> past_errors_;
  static constexpr int kSearchDepth = 5;
  static constexpr int kErrorWindow = 5;
  double Evaluate(int prev_quality, int quality, double rebuffer);
  double Search(int depth, double throughput, double buffer_level,
                int prev_quality, int quality);
};

#endif //MPC_ABR
