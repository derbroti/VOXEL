#ifndef ABR_SCHEMES
#define ABR_SCHEMES

//#include "net/tools/quic/quic_simple_client.h"
#include <stddef.h>
#include <memory>
#include <vector>
#include <map>
#include <string>
#include <unordered_map>

typedef struct {
  size_t size; // Size in bytes
  size_t reliable_size; // Amount of total_size that is attributed to reliable headers and frames
  int quality; // Quality level in range [0-12]
  uint32_t required_frames; // Frame count in range [0-95] (for 4s segments)
} SSIMBasedQuality;

/*
typedef struct {
  uint32_t frames;
  size_t size;
} threshold;
*/

typedef struct {
  std::string mediaRange;
  std::string reliable_frames;
  std::string unreliable_frames;
  size_t size;
  size_t rel_size;
  size_t unrel_size;
  size_t start;
  //std::unordered_map<double, threshold> thresholds;
} segment;

typedef struct {
  std::string baseUrl;
  std::vector<segment> segments;
} repr;

enum DP {GQ, GB, GP, SB};

struct AbrLogLine {
  double playhead_time_;
  double buffer_level_;
  double throughput_;
  int quality_;
  double bitrate_;
  double pause_;
};

class TransportInterface {
	public:
		virtual double AddThroughput() = 0;
		virtual double GetTput() = 0;
		virtual uint32_t GetTime(bool) = 0;
		virtual uint32_t GetTime() = 0;
		virtual uint32_t GetRealTime(bool) = 0;
		virtual double GetSegmentSize(bool) = 0;
};

class BolaAbr;
class ThroughputAbr;
class MpcAbr;


class Dispatcher {
	public:
		Dispatcher(TransportInterface* transport) 
		: transport_(transport) {};

		double GetQuality(BolaAbr &bola, int retry, const std::map<double, SSIMBasedQuality>& ssim_map);
		double GetQuality(ThroughputAbr &tput, int retry);
		double GetQuality(MpcAbr &mpc, int retry);

		int GetPause(BolaAbr &bola);
		int GetPause(ThroughputAbr &tput);
		int GetPause(MpcAbr &mpc);

		int GetBuffer(BolaAbr &bola);
		int GetBuffer(ThroughputAbr &tput);
		int GetBuffer(MpcAbr &mpc);

		void SetBuffer(BolaAbr &bola, int lvl);
		void SetBuffer(ThroughputAbr &tput, int lvl);
		void SetBuffer(MpcAbr &mpc, int lvl);

	private:
		TransportInterface* transport_;
};

class BaseAbr {
public:
	virtual double accept(Dispatcher &dispatcher, DP type, int, const std::map<double, SSIMBasedQuality>&) = 0;
	virtual ~BaseAbr() = 0;

    double buffer_size_;
protected:
  	bool startup;
};

enum ThroughputEstimates {
  kTPcoarse = 0,
  kTPfine,
  kTPjslike,
  kTPmoving
};

class MovingAverage {
 public:
  MovingAverage();
  void AddMeasurement(double bandwidth, double time);
  double GetThroughput();
 private:
  double throughput_slow_;
  double throughput_fast_;
  double cumulative_time_;
  static constexpr double kHalfLifeSlow = 8000;
  static constexpr double kHalfLifeFast = 3000;
};


class Abr {
	public:
		Abr(BaseAbr* abr, TransportInterface* transport) 
		: disp(Dispatcher(transport)),
		  abr_(abr) {};
		Abr() 
		: disp(Dispatcher(nullptr)) {};

	void SetAbr(BaseAbr* abr) {
		abr_ = abr;
	}
	void SetTransport(TransportInterface* transport) {
		disp = Dispatcher(transport);
	}
	double GetQuality(int retry, const std::map<double, SSIMBasedQuality>& ssim_map) {
		return abr_->accept(disp, GQ, retry, ssim_map);
	}
	int GetPause() {
		return abr_->accept(disp, GP, 0, {});
	}
	int GetBuffer() {
		return abr_->accept(disp, GB, 0, {});
	}
	void SetBuffer(int lvl) {
		abr_->accept(disp, SB, lvl, {});
	}
	BaseAbr* instance() {
		return abr_;
	}

private:
	Dispatcher disp;
	BaseAbr* abr_;
};

#endif //ABR_SCHEMES
