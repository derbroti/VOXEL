#ifndef BOLA_ABR
#define BOLA_ABR

#include <vector>
#include <map>
#include <iostream>
#include <cmath>

// time in ms
// size in bits
// bitrate in kbps (equivalent to bits/ms)

typedef struct {
  bool in_progress; // false for new download, true when monitoring download
  int quality; // quality of current download
  double ssim; // intended ssim for current download
  size_t size; // Total segment size in bytes.
  size_t downloaded; // Current download status in bytes.
  // Note that downloaded <= size, with equality meaning the download is ready.
  bool reliable;
} DownloadProgress;
const DownloadProgress kNewDownload = {false, 0, 0.0, 0, 0, true};
const DownloadProgress kInProgress = {true, -1, 0.0, 0, 0, true};
// kInProgress avoids changing state, but does not account for current download

class BaseAbr;
class Dispatcher;

class BolaAbr: public BaseAbr {
 public:
  ~BolaAbr() override;
  BolaAbr(double segment_duration,
          double buffer_size,
          std::vector<double> bitrates,
          std::vector<double> ssims);

  double GetQuality(double throughput, double* pause, int retry, const std::map<double, SSIMBasedQuality>& ssim_map);
  int GetPause();
  int GetBuffer();
  void SetBuffer(int lvl);
  void PreUpdate(double pause, uint32_t walltime, int retry);
  void PostUpdate(double pause, uint32_t walltime, int retry);
  double accept(Dispatcher &dispatcher, DP type, int retry, const std::map<double, SSIMBasedQuality>& ssim_map) override;
  const std::vector<AbrLogLine>& GetLog();

  int pause;

  //private:
    double buffer_level_;
    int last_quality_;
    double placeholder_;
    double vp_;
    double gp_;
    double segment_duration_;
    double ibr_safety_factor_target_;
    double ibr_safety_factor_;
    std::vector<double> bitrates_;
    std::vector<double> utilities_;
    std::vector<double> average_ssim_;
    std::vector<AbrLogLine> log_;
    static constexpr double kBufferLow = 10000;
    static constexpr double kMinThreshold = 2000;
    static constexpr double kSafetyFactor = 0.9;
    static constexpr double kIbrSafetyFactor = 0.5;
    // Generate basic ssim map with one entry per quality.
    void FillSsimMap(std::map<double, SSIMBasedQuality>& ssim_map,
                     const std::vector<double> &sizes_bits);
    // BolaE without ssim_map gives old quality with old utilities_ values
    int BolaE(double buffer_level, double throughput,
              double* pause, int retry,
              const DownloadProgress& progress = kNewDownload);
    int BolaE(double buffer_level, double throughput,
              const std::vector<double>& sizes_bits,
              double* pause, int retry,
              const DownloadProgress& progress = kNewDownload);
    double BolaE(double buffer_level, double throughput,
                 const std::map<double, SSIMBasedQuality>& ssim_map,
                 double* pause, int retry,
                 const DownloadProgress& progress = kNewDownload);
    double Score(double buffer_level, double size_bits, double util);
    double BufferLevelForZeroScore(double utility);
    double MinBufferLevelForQuality(int quality);
    double QualityFromBufferLevel(double buffer_level,
                                  const std::map<double, SSIMBasedQuality>& ssim_map,
                                  int max_quality, int favor_quality);
    int QualityFromThroughput(double throughput,
                              const std::vector<double> &sizes_bits);
    double QualityFromThroughput(double throughput,
                                 const std::map<double, SSIMBasedQuality>& ssim_map);
    double SafeDownloadSizeBits(double buffer_level, double throughput);
    int InsufficientBufferRule(double buffer_level, double throughput,
                               const std::vector<double>& sizes_bits);
};

class BPPMovingAverage {
 public:
  BPPMovingAverage();
  void AddMeasurement(size_t received_bytes, double time);
  double GetThroughput();
  void Reset() {throughput_ = 0; cumulative_time_ = 0; cumulative_size_ = 0; warmed_up_1_ = false; warmed_up_2_ = false;}
  void Print() {std::cerr << "[bpp-mavg] tpi:" << throughput_ << " ct:" << cumulative_time_ << " tp:" << GetThroughput() << std::endl;}
 private:
  double throughput_;
  double cumulative_time_;
  size_t cumulative_size_;
  static constexpr double kHalfLife = 500;
  bool warmed_up_1_;
  bool warmed_up_2_;
  static constexpr double alpha = 0.9;
};
#endif //BOLA_ABR
