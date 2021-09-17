// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
//   TODO(rtenneti): make --host optional by getting IP Address of URL's host.
//
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//
// Standard request/response:
//   quic_client http://www.google.com  --host=${IP}
//   quic_client http://www.google.com --quiet  --host=${IP}
//   quic_client https://www.google.com --port=443  --host=${IP}
//
// Use a specific version:
//   quic_client http://www.google.com --quic_version=23  --host=${IP}
//
// Send a POST instead of a GET:
//   quic_client http://www.google.com --body="this is a POST body" --host=${IP}
//
// Append additional headers to the request:
//   quic_client http://www.google.com  --host=${IP}
//               --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//   quic_client mail.google.com --host=${IP}
//
// Try to connect to a host which does not speak QUIC:
//   Get IP address of the www.example.com
//   IP=`dig www.example.com +short | head -1`
//   quic_client http://www.example.com --host=${IP}

//#define SLST_DEBUG 1

#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <stdio.h>
#include <string>
#include <string.h>
#include <dirent.h>
#include <deque>
#include <algorithm>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/task/task_scheduler/task_scheduler.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/third_party/quic/core/quic_error_codes.h"
#include "net/third_party/quic/core/quic_packets.h"
#include "net/third_party/quic/core/quic_server_id.h"
#include "net/third_party/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quic/platform/api/quic_str_cat.h"
#include "net/third_party/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quic/platform/api/quic_text_utils.h"
#include "net/third_party/spdy/core/spdy_header_block.h"
#include "net/tools/quic/quic_simple_client.h"
#include "net/tools/quic/synchronous_host_resolver.h"
#include "url/gurl.h"
#include "net/third_party/quic/core/quic_types.h"

#include "third_party/libxml/chromium/libxml_utils.h"

#include "abr.h"
#include "bola.h"
#include "mpc.h"
#include "tput.h"

using net::CertVerifier;
using net::CTVerifier;
using net::MultiLogCTVerifier;
using quic::ProofVerifier;
using net::ProofVerifierChromium;
using quic::QuicStringPiece;
using quic::QuicTextUtils;
using net::TransportSecurityState;
using spdy::SpdyHeaderBlock;
using std::cout;
using std::cerr;
using  std::endl; 
using std::string;

// The IP or hostname the quic client will connect to.
string FLAGS_host = "";
// The port to connect to.
int32_t FLAGS_port = 0;
// If set, send a POST with this body.
string FLAGS_body = "";
// If set, contents are converted from hex to ascii, before sending as body of
// a POST. e.g. --body_hex=\"68656c6c6f\"
string FLAGS_body_hex = "";
// A semicolon separated list of key:value pairs to add to request headers.
string FLAGS_headers = "";
// Set to true for a quieter output experience.
bool FLAGS_quiet = false;
// QUIC version to speak, e.g. 21. If not set, then all available versions are
// offered in the handshake.
int32_t FLAGS_quic_version = -1;
// If true, a version mismatch in the handshake is not considered a failure.
// Useful for probing a server to determine if it speaks any version of QUIC.
bool FLAGS_version_mismatch_ok = false;
// If true, an HTTP response code of 3xx is considered to be a successful
// response, otherwise a failure.
bool FLAGS_redirect_is_success = true;
// Initial MTU of the connection.
int32_t FLAGS_initial_mtu = 0;
// buffer length in ms for ABR
int32_t FLAGS_abr_buf = 20000;

double FLAGS_smooth = 0;

std::string FLAGS_features;
extern std::unordered_map<std::string,std::string> feature_map;

std::string FLAGS_abr = "bola";

bool FLAGS_fine = false;

//constexpr double kTargetSSIM = 0.88;

// Contains one entry (map) per segment.
std::vector<std::map<double, SSIMBasedQuality>> ssim_map;
std::vector<double> avg_ssims;

class FakeProofVerifier : public quic::ProofVerifier {
 public:
  quic::QuicAsyncStatus VerifyProof(
      const string& hostname,
      const uint16_t port,
      const string& server_config,
      quic::QuicTransportVersion quic_version,
      quic::QuicStringPiece chlo_hash,
      const std::vector<string>& certs,
      const string& cert_sct,
      const string& signature,
      const quic::ProofVerifyContext* context,
      string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* details,
      std::unique_ptr<quic::ProofVerifierCallback> callback) override {
    return quic::QUIC_SUCCESS;
  }

  quic::QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const std::vector<std::string>& certs,
      const quic::ProofVerifyContext* verify_context,
      std::string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
      std::unique_ptr<quic::ProofVerifierCallback> callback) override {
    return quic::QUIC_SUCCESS;
  }

  std::unique_ptr<quic::ProofVerifyContext> CreateDefaultContext() override {
    return nullptr;
  }
};




class Transport : public TransportInterface {

  public:
    Transport(net::QuicSimpleClient* client, bool fine) : client_(client), fine_(fine) {
      client_->SetFine(fine);
    }

    uint32_t GetTime(bool unrel) override {
      return client_->GetTime(unrel);
    }

    uint32_t GetRealTime(bool unrel) override {
      return client_->GetRealTime(unrel);
    }

    uint32_t GetTime() override {
      return client_->GetTime();
    }

    double GetSegmentSize(bool unrel) override {
      return client_->GetSegmentSize(unrel);
    }

  protected:
    net::QuicSimpleClient* client_;
    bool fine_;
};

class TransportBola : public Transport {
 public:
  TransportBola(net::QuicSimpleClient* client, bool fine) : Transport(client, fine) {}

  double AddThroughput() override {
    uint32_t total_time = client_->GetSumTime(quic::sst_unrel);
    double current_throughput = client_->GetSumThroughput(quic::sst_unrel).first;
    if (current_throughput == 0) {
      current_throughput = client_->GetSumThroughput(quic::sst_rel).first;
      total_time = client_->GetSumTime(quic::sst_rel);
    }
    ma.AddMeasurement(current_throughput, total_time);

    return ma.GetThroughput();
  }

  double GetTput() override {
    return ma.GetThroughput();
  }
 private:
  MovingAverage ma;
};

class TransportSLST : public Transport {
 public:
  double alpha = 0;

  TransportSLST(net::QuicSimpleClient* client, bool fine) : Transport(client, fine) {}

  double AddThroughput() override {
    uint32_t total_time = GetTime();
    double total_size = 0;
    if (fine_) {
      total_size = client_->GetReceivedSize();
    } else {
      total_size = client_->GetSegmentSize();
    }
    double current_throughput = (total_size * 8) / total_time;
    throughput = alpha * throughput + (1.0 - alpha) * current_throughput;

    return GetTput();
  }

  double GetTput() override {
    return throughput;
  }

 private:
  double throughput = 0.0;
};

class TransportHarmonic : public Transport {
 public:
  TransportHarmonic(net::QuicSimpleClient* client, bool fine) : Transport(client, fine) {}

  double AddThroughput() override {
    uint32_t total_time = GetTime();
    double total_size = 0;
    if (fine_) {
      total_size = client_->GetReceivedSize();
    } else {
      total_size = client_->GetSegmentSize();
    }
    double current_throughput = (total_size * 8) / total_time;
    if (throughputs.size() >= kThroughputWindow) {
      throughputs.pop_front();
    }
    throughputs.push_back(current_throughput);

    std::cerr << "[tp_window]";
    for (double tp : throughputs) {
      std::cerr << " " << tp;
    }
    std::cerr << std::endl;

    return GetTput();
  }

  double GetTput() override {
    if (throughputs.empty()) {
      return 0;
    }
    double reciprocal = 0.0;
    for (double tp : throughputs) {
      reciprocal += 1 / tp;
    }
    return throughputs.size() / reciprocal;
  }

 private:
  std::deque<double> throughputs;
  size_t kThroughputWindow = 5;
};

typedef struct {
  int to_st;
  int to_len;
  int from_st;
  int from_len;
} frame_order;


void append_frame_order(std::string range, int offset, std::vector<frame_order> *fo) {
  int st, en, len;
  int idx = 0;
  std::string r;
  std::istringstream iss(range);
  while (std::getline(iss, r, ',')) {
    int sep = r.find("-");
    st = std::stoi(r.substr(0, sep), nullptr, 0 ) - offset;
    en = std::stoi(r.substr(sep + 1),  nullptr, 0 ) - offset;
    len = en - st + 1;
    fo->push_back({st, len, idx, len});
    idx += len;
  }
}


void check_404(const SpdyHeaderBlock &shb, bool keep = true) {
  bool die = false;
  auto status = shb.find(":status");
  if (status != shb.end()) {
    if (status->second == "404") {
      die = true;
      std::cerr << "ERROR got 404 - stopping!" << std::endl;
    }
  } else if (keep) {
    std::cerr << shb.DebugString() << std::endl;
    die = true;
    std::cerr << "ERROR got no HTTP status at all?! - stopping!" << std::endl;
  }

  if (die)
    exit(-1);
}

void fill_segment_body(string &segment_body, const string &response_body, const std::vector<frame_order> &frames_order) {
  for (auto it : frames_order) {
    segment_body.replace(it.to_st, it.to_len, response_body, it.from_st, it.from_len);
  }
}

void generate_loss_information(std::map<quic::QuicStreamOffset, quic::FrameTiming> response_timings, int offset,
    std::vector<frame_order> frames_order, std::string &hole_range, std::string &loss_report, int &loss_size) {
  auto quic_frame_it = response_timings.begin();
  auto first_frame_offset = quic_frame_it->first;
  hole_range.clear();
  loss_report = "[loss]";
  loss_size = 0;

  for (; quic_frame_it != response_timings.end(); ++quic_frame_it) {
    if (quic_frame_it->second.was_lost) {
      int loss_pos = quic_frame_it->first - first_frame_offset;
      int loss_len = quic_frame_it->second.length;
      loss_size += loss_len;

      for (auto it = frames_order.begin(); it != frames_order.end(); ++it) {
        if (it->from_st <= loss_pos && loss_pos < it->from_st + it->from_len) {
          int rem_loss = loss_len;

          while (rem_loss > 0) {
            // End of the video frame range in the interval [0,request_size]
            int video_frame_range_end = it->from_st + it->from_len;
            // If the loss starts somewhere inside the video frame range, that position is used. If not, the loss starts
            // at the beginning of the video frame range.
            int loss_offset_in_request = loss_pos > it->from_st ? loss_pos : it->from_st;
            // The remaining size of the video frame range, i.e., how many bytes of the loss could fit in the current
            // range. video_frame_range_end > loss_offset_in_request always holds because it is either loss_pos or
            // it->from_st. Following the if in line 357 loss_pos < it->from_st + it->from_len, the other case is clear.
            int possible_loss_in_range = video_frame_range_end - loss_offset_in_request;
            int actual_loss_in_range = std::min(rem_loss, possible_loss_in_range);
            int loss_offset_in_range = loss_offset_in_request - it->from_st;
            int loss_offset_in_output = offset + it->to_st + loss_offset_in_range;
            hole_range += std::to_string(loss_offset_in_output) + "-" + std::to_string(loss_offset_in_output + actual_loss_in_range - 1) + ",";
            loss_report+= " " + std::to_string(loss_offset_in_output) + "," + std::to_string(actual_loss_in_range);
            rem_loss -= actual_loss_in_range;
            ++it;
          }
          break;
        }
      }
    }
  }
  // Remove trailing comma
  if (!hole_range.empty()) {
    hole_range.pop_back();
  }
}

int fill_holes(std::string &hole_range, Abr* abr, SpdyHeaderBlock &header_block, int loss_size, net::QuicSimpleClient *client, std::string &segment_body, int segment_start, int segment_duration) {
  std::string loss_report;
  int used_time = 0;
  int remaining_pause = abr->GetBuffer() + segment_duration - (abr->instance()->buffer_size_ - segment_duration) - used_time;
  while (!hole_range.empty() && remaining_pause > quic::kSafetyMargin) {
    std::cerr << "[hole-fill-request] " << hole_range << std::endl;
    std::cerr << "[hole-fill-request] " << loss_size << std::endl;
    header_block[":range"] = string("multibytes=") + hole_range;
    std::string response_body;

    // We only initialize fields that are required by the deadline request.
    quic::DownloadConfig dc = {"deadline",
                               loss_size,
                               loss_size,
                               remaining_pause,
                               0 /*quality*/,
                               {} /*bitrates*/,
                               abr->instance(),
                               client /*client*/,
                               false /*not reliable*/,
                               0 /*segment_duration*/,
                               0, /*segment_no*/
                               nullptr, /* adaptationSet* */
                               nullptr, /* ssim_map */
                               false /*ret__kept*/,
                               0 /*ret__quality*/,
                               0 /*ret__ssim*/,
                               0 /*ret__pause*/};

    client->SendRequestAndWaitForResponse(header_block, /*request_body*/"", /*fin=*/true, /*unrel*/true, &dc);
    check_404(client->latest_response_header_block(), dc.ret__kept);

    auto response_timings = client->latest_response_timings();
    response_body = client->latest_response_body();
    const quic::SubSegmentTiming &segment_timing_unrel = client->latest_segment_timing(true);
    uint32_t pre_resize_body_size = response_body.size();
    int tail_loss_len = loss_size - response_body.size();
    if (response_body.size() < (size_t) loss_size) {
      response_body.resize(loss_size);
    }
    std::vector<frame_order> frames_order;
    append_frame_order(hole_range, segment_start, &frames_order);
    fill_segment_body(segment_body, response_body, frames_order);
    auto have_loss = loss_size - segment_timing_unrel.received_size_;
    if (have_loss) {
      if (tail_loss_len > 0) {
        response_timings.emplace(std::make_pair<quic::QuicStreamOffset, quic::FrameTiming>(pre_resize_body_size, {quic::QuicTime::Zero(), tail_loss_len, true}));
      }
      generate_loss_information(response_timings,
                                segment_start,
                                frames_order,
                                hole_range,
                                loss_report,
                                loss_size);
    } else {
      hole_range.clear();
      loss_report.clear();
      loss_size = 0;
    }
    int dl_time = client->GetRealTime(quic::sst_unrel);
    used_time += dl_time;
    remaining_pause -= dl_time;
    std::cerr << "[hole-fill]"
              << " fill:" << segment_timing_unrel.received_size_
              << " loss:" << loss_size
              << " dl:" << dl_time
              << " rp:" << remaining_pause
              << std::endl;
  }
  hole_range.clear();
  if (!loss_report.empty()) {
    std::cerr << loss_report << std::endl;
  }
  return used_time;
}

std::string get_subrange(const std::string &range, size_t count) {
  if (count == 0) {
    return "";
  }
  size_t pos = 0;
  size_t ranges_found = 0;
  while (pos < range.size() && ranges_found < count) {
    size_t next = range.find(',', pos);
    if (next == std::string::npos) {
      // Range after last comma
      pos = range.size();
    } else {
      pos = next + 1;
    }
    ranges_found++;
  }
  if (ranges_found < count) {
    std::cerr << "ERROR: More ranges requested than exist." << std::endl;
    std::cerr << "ranges: " << range << std::endl;
    std::cerr << "requested: " << count << std::endl;
    exit(1);
  }
  if (pos == range.size()) {
    return range;
  }
  // Remove trailing comma
  return range.substr(0, pos - 1);
}

int parse_feature_flag() {
  // thresholds attribute has format thresholds="ssim_1:frames:size,ssim_2:frames:size,..."
  // e.g. thresholds="0.5:0:0,0.88:1:23345,0.95:0:0,0.99:1:23345"
  // Separate comma list first.
  std::vector<std::string> key_value_pairs;
  size_t pos = 0;
  std::cerr << "[features] " << FLAGS_features << std::endl;
  while (FLAGS_features.find('#', pos) != std::string::npos) {
    size_t next = FLAGS_features.find('#', pos);
    key_value_pairs.push_back(FLAGS_features.substr(pos, next - pos));
    pos = next + 1;
  }
  // Add last entry
  if (pos != FLAGS_features.size()) {
    key_value_pairs.push_back(FLAGS_features.substr(pos, FLAGS_features.size() - pos));
  }

  for (auto &&key_value : key_value_pairs) {
    pos = 0;
    size_t next = key_value.find(':', pos);
    if (next == std::string::npos) {
      return 1;
    }
    std::string key = key_value.substr(pos, next - pos);
    pos = next + 1;
    std::string value = key_value.substr(pos, key_value.size() - pos);
    feature_map[key] = value;
  }
  return 0;
}

void print_ssim_map(std::vector<std::map<double, SSIMBasedQuality>> map) {
  uint32_t segment_count = 1;
  for (auto &segment_ssim_map : map) {
    std::cerr << "segment: " << segment_count;
    for (auto &entry : segment_ssim_map) {
      std::cerr << " [" << entry.first << ":" << entry.second.required_frames << ":" << entry.second.quality << "]";
    }
    std::cerr << std::endl;
    segment_count++;
  }
}

///////////////////



//MAIN



///////////////////


int main(int argc, char* argv[]) {

  auto t_start = std::chrono::system_clock::now();

  std::cerr << "[start] " << std::chrono::duration_cast<std::chrono::milliseconds>(t_start.time_since_epoch()).count() << std::endl;
  
  base::CommandLine::Init(argc, argv);
  base::CommandLine* line = base::CommandLine::ForCurrentProcess();
  const base::CommandLine::StringVector& urls = line->GetArgs();
  base::TaskScheduler::CreateAndStartWithDefaultParams("quic_client");

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));

  if (line->HasSwitch("h") || line->HasSwitch("help") || urls.empty()) {
    const char* help_str =
        "Usage: quic_client [options] <url>\n"
        "\n"
        "<url> with scheme must be provided (e.g. http://www.google.com)\n\n"
        "Options:\n"
        "-h, --help                         show this help message and exit\n"
        "--host=<host>                      specify the IP address of the hostname to connect to\n"     
        "--port=<port>                      specify the port to connect to\n"
        "--body=<body>                      specify the body to post\n"
        "--body_hex=<body_hex>              specify the body_hex to be printed out\n"
        "--headers=<headers>                specify a semicolon separated list of key:value pairs to add to request headers\n"
        "-q, --quiet                        specify for a quieter output experience\n"
        "--quic-version=<quic version>      specify QUIC version to speak\n"
        "--version_mismatch_ok              if specified a version mismatch in the handshake is not considered a failure\n"
        "--redirect_is_success              if specified an HTTP response code of 3xx is considered to be a successful response, otherwise a failure\n"
        "--initial_mtu=<initial_mtu>        specify the initial MTU of the connection\n" 
        "--disable-certificate-verification do not verify certificates\n"
        "--abr_buf=<ms>                     specify the amount (in ms) of buffer for the ABR to use\n"
        "--abr=<bola|bpp|mpc|tput> specify the ABR algorithm to use\n"
        "--feature=<0-2>                    specify the features bpp should use (0:nobola,1:abort,2:keep)\n"
        "--fine                             if specified the transport layer provides a fine-grained signal for the throughput calculation\n";
    cerr << help_str;
    exit(0);
  }
  if (line->HasSwitch("host")) {
    FLAGS_host = line->GetSwitchValueASCII("host");
  }
  if (line->HasSwitch("port")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("port"), &FLAGS_port)) {
      std::cerr << "--port must be an integer\n";
      return 1;
    }
  }
  if (line->HasSwitch("body")) {
    FLAGS_body = line->GetSwitchValueASCII("body");
  }
  if (line->HasSwitch("body_hex")) {
    FLAGS_body_hex = line->GetSwitchValueASCII("body_hex");
  }
  if (line->HasSwitch("headers")) {
    FLAGS_headers = line->GetSwitchValueASCII("headers");
  }
  if (line->HasSwitch("q") || line->HasSwitch("quiet")) {
    FLAGS_quiet = true;
  }
  if (line->HasSwitch("quic-version")) {
    int quic_version;
    if (base::StringToInt(line->GetSwitchValueASCII("quic-version"),
                          &quic_version)) {
      FLAGS_quic_version = quic_version;
    }
  }
  if (line->HasSwitch("version_mismatch_ok")) {
    FLAGS_version_mismatch_ok = true;
  }
  if (line->HasSwitch("redirect_is_success")) {
    FLAGS_redirect_is_success = true;
  }
  if (line->HasSwitch("initial_mtu")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("initial_mtu"),
                           &FLAGS_initial_mtu)) {
      std::cerr << "--initial_mtu must be an integer\n";
      return 1;
    }
  }
  if (line->HasSwitch("abr")) {
    FLAGS_abr = line->GetSwitchValueASCII("abr");
  }
  if (line->HasSwitch("abr_buf")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("abr_buf"),
                           &FLAGS_abr_buf)) {
      std::cerr << "--abr_buf must be an integer\n";
      return 1;
    }
  }
  if (line->HasSwitch("smooth")) {
    if (!base::StringToDouble(line->GetSwitchValueASCII("smooth"),
                           &FLAGS_smooth)) {
      std::cerr << "--smooth must be a double\n";
      return 1;
    }
  }

  if (line->HasSwitch("feature")) {
    FLAGS_features = line->GetSwitchValueASCII("feature");
    if (parse_feature_flag() != 0) {
      std::cerr << "Error while parsing feature flag.\n";
      return 1;
    }
  }
  if (line->HasSwitch("fine")) {
    FLAGS_fine = true;
  }

  VLOG(1) << "server host: " << FLAGS_host << " port: " << FLAGS_port
          << " body: " << FLAGS_body << " headers: " << FLAGS_headers
          << " quiet: " << FLAGS_quiet
          << " quic-version: " << FLAGS_quic_version
          << " version_mismatch_ok: " << FLAGS_version_mismatch_ok
          << " redirect_is_success: " << FLAGS_redirect_is_success
          << " initial_mtu: " << FLAGS_initial_mtu;

  base::AtExitManager exit_manager;
  base::MessageLoopForIO message_loop;

  // Determine IP address to connect to from supplied hostname.
  quic::QuicIpAddress ip_addr;

  GURL url(urls[0]);
  string host = FLAGS_host;
  if (host.empty()) {
    host = url.host();
  }
  int port = FLAGS_port;
  if (port == 0) {
    port = url.EffectiveIntPort();
  }
  if (!ip_addr.FromString(host)) {
    net::AddressList addresses;
    int rv = net::SynchronousHostResolver::Resolve(host, &addresses);
    if (rv != net::OK) {
      LOG(ERROR) << "Unable to resolve '" << host
                 << "' : " << net::ErrorToShortString(rv);
      return 1;
    }
    ip_addr =
        quic::QuicIpAddress(quic::QuicIpAddressImpl(addresses[0].address()));
  }

  string host_port = quic::QuicStrCat(ip_addr.ToString(), ":", port);
  VLOG(1) << "Resolved " << host << " to " << host_port << endl;

  // Build the client, and try to connect.
  quic::QuicServerId server_id(url.host(), url.EffectiveIntPort(),
                               net::PRIVACY_MODE_DISABLED);
  quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();
  if (FLAGS_quic_version != -1) {
    versions.clear();
    versions.push_back(quic::ParsedQuicVersion(
        quic::PROTOCOL_QUIC_CRYPTO,
        static_cast<quic::QuicTransportVersion>(FLAGS_quic_version)));
  }
  // For secure QUIC we need to verify the cert chain.
  std::unique_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
  std::unique_ptr<TransportSecurityState> transport_security_state(
      new TransportSecurityState);
  std::unique_ptr<MultiLogCTVerifier> ct_verifier(new MultiLogCTVerifier());
  std::unique_ptr<net::CTPolicyEnforcer> ct_policy_enforcer(
      new net::DefaultCTPolicyEnforcer());
  std::unique_ptr<quic::ProofVerifier> proof_verifier;
  if (line->HasSwitch("disable-certificate-verification")) {
    proof_verifier.reset(new FakeProofVerifier());
  } else {
    proof_verifier.reset(new ProofVerifierChromium(
        cert_verifier.get(), ct_policy_enforcer.get(),
        transport_security_state.get(), ct_verifier.get()));
  }
  net::QuicSimpleClient client(quic::QuicSocketAddress(ip_addr, port),
                               server_id, versions, std::move(proof_verifier));
  client.set_initial_max_packet_length(
      FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : quic::kDefaultMaxPacketSize);
  if (!client.Initialize()) {
    cerr << "Failed to initialize client." << endl;
    return 1;
  }
  if (!client.Connect()) {
    quic::QuicErrorCode error = client.session()->error();
    if (FLAGS_version_mismatch_ok && error == quic::QUIC_INVALID_VERSION) {
      cerr << "Server talks QUIC, but none of the versions supported by "
           << "this client: " << ParsedQuicVersionVectorToString(versions)
           << endl;
      // Version mismatch is not deemed a failure.
      return 0;
    }
    cerr << "Failed to connect to " << host_port
         << ". Error: " << quic::QuicErrorCodeToString(error) << endl;
    return 1;
  }
  if (!FLAGS_quiet)
    cerr << "[connected] " << host_port <<  endl;

  // Construct the string body from flags, if provided.
  string body = FLAGS_body;
  if (!FLAGS_body_hex.empty()) {
    DCHECK(FLAGS_body.empty()) << "Only set one of --body and --body_hex.";
    body = quic::QuicTextUtils::HexDecode(FLAGS_body_hex);
  }

  // Construct a GET or POST request for supplied URL.
  SpdyHeaderBlock header_block;
  header_block[":method"] = body.empty() ? "GET" : "POST";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.host();
  header_block[":path"] = url.path();

  // Append any additional headers supplied on the command line.
  for (quic::QuicStringPiece sp :
       quic::QuicTextUtils::Split(FLAGS_headers, ';')) {
    quic::QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&sp);
    if (sp.empty()) {
      continue;
    }
    std::vector<quic::QuicStringPiece> kv = quic::QuicTextUtils::Split(sp, ':');
    quic::QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[0]);
    quic::QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[1]);
    header_block[kv[0]] = kv[1];
  }

  // Make sure to store the response, for later output.
  client.set_store_response(true);

  // Print request and response details.
  if (!FLAGS_quiet) {
    cerr << "MANIFEST Request:" << endl;
    cerr << "headers:" << header_block.DebugString();
    cerr << "body: " << body << endl;
  }

  // Send the request for manifest
  client.SendRequestAndWaitForResponse(header_block, body, /*fin=*/true, /*unrel*/false);
  check_404(client.latest_response_header_block());

  if (!FLAGS_quiet) {
    cerr << "Response:" << endl;
    cerr << "headers: " << client.latest_response_headers() << endl;
  }
  string response_body = client.latest_response_body();
  if (!FLAGS_body_hex.empty()) {
    // Assume response is binary data.
    if (!FLAGS_quiet)
    cerr << "body:\n" << quic::QuicTextUtils::HexDump(response_body) << endl;
  } else {
    if (!FLAGS_quiet)
    cerr << "body: " << response_body << endl;
  }
  if (!FLAGS_quiet)
  cerr << "trailers: " << client.latest_response_trailers() << "\n\n" << endl;



  std::string xml_body(response_body);
  XmlReader xml_reader;
  if (!xml_reader.Load(xml_body))
  {
    cerr << "COULD NOT READ XML" << endl;
    return -1;
  }
  else {
  //  cerr << xml_body << endl;
  }

  size_t total_written = 0;
  std::map< quic::QuicStreamOffset, quic::FrameTiming > response_timings;


  std::map< uint32_t, repr > adaptationSet;
  uint32_t current_repr_bw = 0;

  int segment_duration = 0;

  while (xml_reader.Read()) 
  {
    xml_reader.SkipToElement();
    std::string node_name(xml_reader.NodeName());

    if (node_name == "Representation" && !xml_reader.IsClosingElement()) {
      std::string type;
      std::string avg_ssim;
      xml_reader.NodeAttribute("mimeType", &type);
      xml_reader.NodeAttribute("avgSSIM", &avg_ssim);
      avg_ssims.push_back(std::stod(avg_ssim));

      if(type.rfind("audio", 0) == 0) {
        std::cerr << "found audio: ignoring for now" << std::endl;
      }

      //std::cerr << "found repr" << std::endl;
      std::string bw;
      unsigned int ibw;

      xml_reader.NodeAttribute("bandwidth", &bw);
      ibw = std::stoi(bw, nullptr, 0);
      current_repr_bw = (uint32_t)(ibw / 1000);

      adaptationSet.insert(std::pair<uint32_t, repr>(current_repr_bw, {"", {}}));
    }
    else
    if (node_name == "BaseURL" && !xml_reader.IsClosingElement()) 
    {
      std::string file_name;
      xml_reader.ReadElementContent(&file_name);
      adaptationSet[current_repr_bw].baseUrl = file_name;
    }
    else 
    if (node_name == "Initialization" && !xml_reader.IsClosingElement())
    {
      std::string range;
      xml_reader.NodeAttribute("range", &range);

      size_t size = std::stoi(range.substr(range.find("-")+1, range.length()), nullptr, 0) +1;
      adaptationSet[current_repr_bw].segments.push_back({range, /*mr*/
                                                         range, /*relr*/
                                                         ""   , /*unrelr*/
                                                         size , /*size*/
                                                         size , /*relsize*/
                                                         0    , /*unrelsize*/
                                                         0   /*start*/ //,
                                                         //{}});
                                                        });
    }
    else if (node_name == "SegmentList" && !xml_reader.IsClosingElement())
    {
      std::string timescale, duration;
      xml_reader.NodeAttribute("timescale", &timescale);
      xml_reader.NodeAttribute("duration", &duration);

      segment_duration = (std::stoi(duration, nullptr, 0) / std::stoi(timescale, nullptr, 0) ) * 1000;
    }
    else if (node_name == "SegmentURL" && !xml_reader.IsClosingElement())
    {
      int st = 0;
      int en = 0;

      std::string media_range, ssims, reliable_frames, unreliable_frames, reliable_size;

      xml_reader.NodeAttribute("mediaRange", &media_range);
      xml_reader.NodeAttribute("reliable", &reliable_frames);
      xml_reader.NodeAttribute("unreliable", &unreliable_frames);
      xml_reader.NodeAttribute("ssims", &ssims);
      xml_reader.NodeAttribute("reliableSize", &reliable_size);

      st = std::stoi( media_range.substr(media_range.find("=")+1, media_range.find("-")), nullptr, 0 );
      en = std::stoi( media_range.substr(media_range.find("-")+1, media_range.length()),  nullptr, 0 );

      int rel_size = std::stoi(reliable_size, nullptr, 0);
      int segment_size = en - st + 1;
      int unrel_size = segment_size - rel_size;

      //std::unordered_map<double, threshold> threshold_map;
      if (ssims != "") {
        // ssims attribute has format ssims="ssim_1:frames:size,ssim_2:frames:size,..."
        // e.g. ssims="0.5:0:0,0.88:1:23345,0.95:0:0,0.99:1:23345"
        // Separate comma list first.
        std::vector<std::string> ssim_values;
        size_t pos = 0;
        while (ssims.find(',', pos) != std::string::npos) {
          size_t next = ssims.find(',', pos);
          ssim_values.push_back(ssims.substr(pos, next - pos));
          pos = next + 1;
        }
        // Add last entry
        if (pos != ssims.size()) {
          ssim_values.push_back(ssims.substr(pos, ssims.size() - pos));
        }

        size_t curr_segment_no = adaptationSet[current_repr_bw].segments.size() - 1;
        for (auto &&value : ssim_values) {
          pos = 0;
          size_t next = value.find(':', pos);
          double ssim = std::stod(value.substr(pos, next - pos));
          pos = next + 1;
          next = value.find(':', pos);
          uint32_t frames = std::stoi(value.substr(pos, next - pos));
          pos = next + 1;
          size_t size = std::stol(value.substr(pos, value.size() - pos));

          //current_repr_bw is used as a filler, will be replaced by proper q value, once we have parsed all qualities
          // adaptationSet contains initialization segment, which we do not want to count.
          if (ssim_map.size() < curr_segment_no + 1) {
            ssim_map.emplace_back();
            if (ssim_map.size() != curr_segment_no + 1) {
              std::cerr << "ERROR: ssim_map has unexpected size. (" << ssim_map.size() << " != " << curr_segment_no + 1 << ")\n";
              exit(1);
            }
          }
          ssim_map[curr_segment_no][ssim] = {size + rel_size, rel_size, current_repr_bw, frames};
        }
      }

      adaptationSet[current_repr_bw].segments.push_back({media_range,
                                                         reliable_frames,
                                                         unreliable_frames,
                                                         segment_size, 
                                                         rel_size, 
                                                         unrel_size, 
                                                         st//,
                                                         //threshold_map});
                                                         });
    }
  }

  std::cerr << "[legend] bitrates/throughput:kbps durations/buffer/times:ms sizes/loss:bytes" << std::endl;

  std::vector<double> bitrates;
  //insert in reverse order so lowest quality (assuming an ordered list...) is first
  std::cerr << "[bitrates] ";
  for (auto& adap: adaptationSet) {
    std::cerr << adap.first << " ";
    bitrates.insert(bitrates.end(), adap.first);
  }
  std::cerr << std::endl;

  // hack: replace bitrates with q indizes
  for (auto &segment_ssim_map : ssim_map) {
    for (auto &ssim : segment_ssim_map) {
      ssim.second.quality =
          std::distance(bitrates.begin(), std::find(bitrates.begin(), bitrates.end(), ssim.second.quality));
    }
  }
  uint32_t segment_count  = 1;
  for (auto &segment_ssim_map : ssim_map) {
    std::map<int, bool> distinct_qualities;
    for (auto &entry : segment_ssim_map) {
      distinct_qualities[entry.second.quality] = true;
    }
    if (distinct_qualities.size() != bitrates.size()) {
      std::cerr << "Warning: segment " << segment_count << " has missing quality entries: ("
      << distinct_qualities.size() << " < " << bitrates.size() << ")" << std::endl;
    }
    segment_count++;
  }
  segment_count = 1;
  if (feature_map.find("no_drop") != feature_map.end()) {
    for (auto &segment_ssim_map : ssim_map) {
      std::vector<std::pair<double, SSIMBasedQuality>> temp_map(bitrates.size());
      for ( auto it = segment_ssim_map.rbegin(); it != segment_ssim_map.rend(); it++) {
        if (temp_map[it->second.quality].second.required_frames < it->second.required_frames) {
          temp_map[it->second.quality] = {it->first, it->second};
        }
      }
      segment_ssim_map.clear();
      for (auto &temp_entry : temp_map) {
        segment_ssim_map[temp_entry.first] = temp_entry.second;
      }
      if (segment_ssim_map.size() != bitrates.size()) {
        std::cerr << "Warning: (no_drop) segment " << segment_count << " has missing quality entries: ("
                  << segment_ssim_map.size() << " < " << bitrates.size() << ")" << std::endl;
      }
      segment_count++;
    }
  }
  std::reverse(avg_ssims.begin(), avg_ssims.end());
  std::cerr << "[avg-ssims]";
  for (auto avg : avg_ssims) {
    std::cerr << " " << avg;
  }
  std::cerr << std::endl;

  auto &first_segment = ssim_map.front();
  std::cerr << "First segment: ";
  for (auto &ssim : first_segment) {
    std::cerr << " [" << ssim.first << ":" << ssim.second.required_frames << ":" << ssim.second.quality << "]";
  }
  std::cerr << "\n";


  //init segment is not a "segment"
  std::cerr << "[segments] num:" << adaptationSet[bitrates[0]].segments.size()-1 << " len:" << segment_duration << std::endl;


  /////////
  /// ABR

  Abr abr;

  BolaAbr *bola;
  MpcAbr *mpc;
  ThroughputAbr *tput;

  TransportInterface* t;
  if (FLAGS_fine) {
    std::cerr << "[fine]" << std::endl;
  }
  if (FLAGS_abr == "tput") {
    TransportSLST *t_slst = new TransportSLST(&client, FLAGS_fine);
    t_slst->alpha = FLAGS_smooth;
    t = t_slst;
    std::cerr << "[smooth] " << t_slst->alpha << std::endl;
  } else if (FLAGS_abr == "bola" || FLAGS_abr == "bpp") {
    TransportBola *t_b = new TransportBola(&client, FLAGS_fine);
    t = t_b;
  } else if (FLAGS_abr == "mpc") {
    TransportHarmonic *t_h = new TransportHarmonic(&client, FLAGS_fine);
    t = t_h;
    std::cerr << "[harmonic]" << std::endl;
  } else {
    std::cerr << "Unknown abr selected!" << std::endl;
    exit(-1);
  }
  abr.SetTransport(t);

  if (FLAGS_abr == "bola" || FLAGS_abr == "bpp") {
    bola = new BolaAbr(segment_duration, (double)(FLAGS_abr_buf), bitrates, avg_ssims);
    abr.SetAbr(bola);
  } else if (FLAGS_abr == "tput") {
    tput = new ThroughputAbr(segment_duration,(double)(FLAGS_abr_buf), bitrates);
    abr.SetAbr(tput);
  } else if (FLAGS_abr == "mpc") {
    mpc = new MpcAbr(segment_duration, (double)(FLAGS_abr_buf), bitrates);
    abr.SetAbr(mpc);
  } else {
    std::cerr << "Unknown abr selected!" << std::endl;
    exit(-1);
  }
  std::cerr << "[abr] " << FLAGS_abr << std::endl;

  //download init segment first
  header_block[":path"] = "/" + adaptationSet[bitrates[0]].baseUrl;
  header_block[":range"] = string("bytes=") + adaptationSet[bitrates[0]].segments[0].mediaRange;

  std::cerr << std::endl;


  auto t_init_start = std::chrono::system_clock::now();

  response_body.clear();
  client.SendRequestAndWaitForResponse(header_block, /*request_body*/"", /*fin=*/true, /*unrel*/false);
  check_404(client.latest_response_header_block());
  response_timings = client.latest_response_timings();
  response_body = client.latest_response_body();
  total_written += std::fwrite(response_body.data(), sizeof response_body[0], response_body.size(), stdout);
  fflush(stdout);

  std::cerr << "[segment]"
            << " #:" << 0 
            << " br:" << (uint32_t) bitrates[0] 
            << " ss:" << (uint32_t) client.latest_segment_timing(false).segment_size_
            << " ssr:" << (uint32_t) client.latest_segment_timing(false).segment_size_
            << " ssu:0" 
            << " loss:0" 
            << " @:" << adaptationSet[bitrates[0]].segments[0].mediaRange 
            << " n:" << adaptationSet[bitrates[0]].baseUrl << std::endl;

  std::cerr << "[time]"
      << " s:" << std::chrono::duration_cast<std::chrono::milliseconds>(t_init_start - t_start).count()
      << " r:" << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - t_init_start).count()
      << " u:" << "0"
      << " dlr:" << client.latest_segment_timing(false).time_
      << " dlu:" << "0"
      << std::endl,
  std::cerr << "[throughput] mavg:0 r:" << client.latest_segment_timing(false).throughput_ << " u:0" << std::endl;

  std::cerr << std::endl;
  std::cerr << "[buffer] 0" << std::endl;

  auto num_segments = adaptationSet[bitrates[0]].segments.size();

  int retry = 0;
  int bola_quality = 0;
  double bola_pause = 0;
  double bpp_ssim = 0;
  string segment_body;
  int pause = 0;
  string hole_range;
  string loss_report;
  int loss_size = 0;
  int q = 0;
  double ssim = 0.0;
  SSIMBasedQuality ssim_q;
  std::chrono::system_clock::time_point t_req_start;
  for (uint32_t i = 1; i < num_segments; ++i) {
    //set quality of first segment fix to lowest
    if (i == 1) {
      q = 0;
    } 
    else if (retry) {
      if (FLAGS_abr == "bola") {
        t->AddThroughput();
        q = bola_quality;
        pause = bola_pause;
      } else if (FLAGS_abr == "bpp") {
        //TODO Remove bola_pause
        t->AddThroughput();
        std::cerr << "[abort-tp]"
                  << " s:" << std::chrono::duration_cast<std::chrono::milliseconds>(t_req_start - t_start).count()
                  << " tp:"  << client.GetSumThroughput()
                  << std::endl;

        pause = bola_pause;
        ssim_q = ssim_map[i -1].at(bpp_ssim);
        q = ssim_q.quality;
      } else {
        std::cerr << "ERROR: This abr should not be able to retry: " << FLAGS_abr << std::endl;
        exit(1);
      }
    }
    else {
      if (FLAGS_abr == "bpp" || (FLAGS_abr == "bola" && feature_map.find("bola_enhanced") != feature_map.end())) {
        ssim = abr.GetQuality(retry, ssim_map[i - 1]);
        ssim_q = ssim_map[i -1].at(ssim);
        q = ssim_q.quality;
      }
      else {
        q = (int) abr.GetQuality(retry, {});
      }
      pause = abr.GetPause();
    }

    usleep(pause * 1000);
    std::cerr << std::endl
      << "[trying-segment]"
      << " #:" << i
      << " ssim:" << ((retry) ? bpp_ssim : ssim)
      << " br:" << (uint32_t) bitrates[q]
      << " ss:" << (uint32_t) (adaptationSet[bitrates[q]].segments[i].size)
      << " ssr:" << (uint32_t) adaptationSet[bitrates[q]].segments[i].rel_size
      << " ssu:" << (uint32_t) adaptationSet[bitrates[q]].segments[i].unrel_size
      << " @:" << adaptationSet[bitrates[q]].segments[i].mediaRange
      << " n:" << adaptationSet[bitrates[q]].baseUrl 
      << " re:" << retry
      << std::endl;

    header_block[":path"] = "/" + adaptationSet[bitrates[q]].baseUrl;

    std::string reliable_frames = adaptationSet[bitrates[q]].segments[i].reliable_frames;
    std::string unreliable_frames = adaptationSet[bitrates[q]].segments[i].unreliable_frames;

    client.ResetAllTimings();

    segment_body.clear();
    segment_body.resize(adaptationSet[bitrates[q]].segments[i].size, '\0');

    t_req_start = std::chrono::system_clock::now();

    std::string required_unreliable_frames = unreliable_frames;
    std::string optional_unreliable_frames;
    // This is used in the reliable download to estimate the required time for the _complete_ download so we use the
    // complete size.
    size_t required_reliable_size = adaptationSet[bitrates[q]].segments[i].size;
    size_t required_unreliable_size = adaptationSet[bitrates[q]].segments[i].unrel_size;
    size_t optional_unreliable_size = 0;
    // These two are only used by bpp. A dummy value is used here to retain backwards compatibility with MPDs without
    // the thresholds attribute. Note that bpp requires the threshold attribute.
    size_t unreliable_fallback_size = 0;
    size_t reliable_fallback_size = 0;

    if (FLAGS_abr == "bpp") {
      required_unreliable_frames =
          get_subrange(unreliable_frames, ssim_q.required_frames);
      required_unreliable_size = ssim_q.size - ssim_q.reliable_size;
      required_reliable_size = ssim_q.size;
      if (required_unreliable_frames.size() < unreliable_frames.size()) {
        if (required_unreliable_frames.empty()) {
          optional_unreliable_frames = unreliable_frames;
        } else {
          optional_unreliable_frames = unreliable_frames.substr(required_unreliable_frames.size() + 1, unreliable_frames.size() - required_unreliable_frames.size());
        }
        optional_unreliable_size = adaptationSet[bitrates[q]].segments[i].unrel_size - required_unreliable_size;
      }

      //TODO-Jan26: Refactor/Remove
      //unreliable_fallback_size = adaptationSet[bitrates[(q > 0)?q-1:0]].segments[i].thresholds[kTargetSSIM].size;
      //reliable_fallback_size = adaptationSet[bitrates[(q > 0)?q-1:0]].segments[i].rel_size + unreliable_fallback_size;

      std::cerr << "[bpp-request-sizes]"
        << " ssr:" << adaptationSet[bitrates[q]].segments[i].rel_size
        << " ssu:" << required_unreliable_size
        << " sso:" << optional_unreliable_size
        << std::endl;
    }

    if (!reliable_frames.empty()) {
      header_block[":range"] = string("multibytes=") + reliable_frames;
      response_body.clear();

      quic::DownloadConfig dc = {FLAGS_abr,
                                 required_reliable_size,
                                 reliable_fallback_size,
                                 abr.GetBuffer(),
                                 q /* current quality level index */,
                                 bitrates,
                                 abr.instance(),
                                 &client /*client*/,
                                 true /*reliable*/,
                                 segment_duration,
                                 i, /*segment_no*/
                                 &adaptationSet,
                                 &ssim_map[i - 1],
                                 false /*ret__kept*/,
                                 0 /*ret__quality*/,
                                 0 /*ret__ssim*/,
                                 0 /*ret__pause*/};

      client.SendRequestAndWaitForResponse(header_block, /*request_body*/"", /*fin=*/true, /*unrel*/false, &dc);
      check_404(client.latest_response_header_block(), dc.ret__kept);

      abr.SetBuffer(abr.GetBuffer() - t->GetRealTime(/*unrel*/false));
      
      if (!dc.ret__kept) { // force retry of current segment
        // bpp will ignore the following two
        bola_quality = dc.ret__quality;
        bola_pause = dc.ret__pause;
        bpp_ssim = dc.ret__ssim;

        retry += 1;
        --i; continue;
      }

      response_timings = client.latest_response_timings();
      response_body = client.latest_response_body();

      std::vector<frame_order> frames_order;
      append_frame_order(reliable_frames, adaptationSet[bitrates[q]].segments[i].start, &frames_order);
      fill_segment_body(segment_body, response_body, frames_order);
    }

    auto t_rel_stop = std::chrono::system_clock::now();
    auto t_unrel_stop = t_rel_stop;


    if (!required_unreliable_frames.empty()) {
      header_block[":range"] = string("multibytes=") + required_unreliable_frames;
      response_body.clear();

      quic::DownloadConfig dc = {FLAGS_abr,
                                 required_unreliable_size,
                                 unreliable_fallback_size,
                                 abr.GetBuffer(),
                                 q /* current quality level index */,
                                 bitrates,
                                 abr.instance(),
                                 &client /*client*/,
                                 false /*not reliable*/,
                                 segment_duration,
                                 i, /*segment_no*/
                                 &adaptationSet,
                                 &ssim_map[i - 1],
                                 false /*ret__kept*/,
                                 0 /*ret__quality*/,
                                 0 /*ret__ssim*/,
                                 0 /*ret__pause*/};

      client.SendRequestAndWaitForResponse(header_block, /*request_body*/"", /*fin=*/true, /*unrel*/true, &dc);
      check_404(client.latest_response_header_block(), dc.ret__kept);

      abr.SetBuffer(abr.GetBuffer() - t->GetRealTime(/*unrel*/true));

      if (!dc.ret__kept) { // force retry of current segment
        // bpp will ignore the following two
        bola_quality = dc.ret__quality;
        bola_pause = dc.ret__pause;
        bpp_ssim = dc.ret__ssim;

        retry += 1;
          --i; continue;
      }

      response_timings = client.latest_response_timings();
      response_body = client.latest_response_body();
      uint32_t pre_resize_body_size = response_body.size();
      int tail_loss_len = required_unreliable_size - response_body.size();
      if (response_body.size() < required_unreliable_size) {
        response_body.resize(required_reliable_size);
      }
      std::vector<frame_order> frames_order;
      append_frame_order(required_unreliable_frames, adaptationSet[bitrates[q]].segments[i].start, &frames_order);
      fill_segment_body(segment_body, response_body, frames_order);

      t_unrel_stop = std::chrono::system_clock::now();

      auto have_loss = required_unreliable_size - client.latest_segment_timing(true).received_size_;
      if (have_loss) {
        if (tail_loss_len > 0) {
          response_timings.emplace(std::make_pair<quic::QuicStreamOffset, quic::FrameTiming>(pre_resize_body_size, {quic::QuicTime::Zero(), tail_loss_len, true}));
        }
        generate_loss_information(response_timings,
                                  adaptationSet[bitrates[q]].segments[i].start,
                                  frames_order,
                                  hole_range,
                                  loss_report,
                                  loss_size);
        if (abr.GetBuffer() + segment_duration - (abr.instance()->buffer_size_ - segment_duration) > quic::kSafetyMargin) {
          int used_time = fill_holes(hole_range, &abr, header_block, loss_size, &client, segment_body, adaptationSet[bitrates[q]].segments[i].start, segment_duration);
          abr.SetBuffer(abr.GetBuffer() - used_time);
        } else {
          std::cerr << loss_report << std::endl;
        }
      } else {
        hole_range.clear();
        loss_report.clear();
        loss_size = 0;
      }
    }

    if (!optional_unreliable_frames.empty()) {
      if (abr.GetBuffer() + segment_duration - (abr.instance()->buffer_size_ - segment_duration) > quic::kSafetyMargin) {
        std::cerr << "[loading-optional]" << std::endl;
        int used_time = fill_holes(optional_unreliable_frames,
                                   &abr,
                                   header_block,
                                   optional_unreliable_size,
                                   &client,
                                   segment_body,
                                   adaptationSet[bitrates[q]].segments[i].start,
                                   segment_duration);
        abr.SetBuffer(abr.GetBuffer() - used_time);
      } else {
        std::cerr << "[skipping-optional] " << optional_unreliable_frames << std::endl;
      }
    }


    total_written += std::fwrite(segment_body.data(), sizeof segment_body[0], segment_body.size(), stdout);
    fflush(stdout);


    std::cerr << "[segment]" 
      << " #:" << i
      << " ssim:" << ((retry) ? bpp_ssim : ssim)
      << " br:" << (uint32_t) bitrates[q]
      << " ss:" << (uint32_t) adaptationSet[bitrates[q]].segments[i].size
      << " ssr:" << (uint32_t) adaptationSet[bitrates[q]].segments[i].rel_size
      << " ssu:" << (uint32_t) adaptationSet[bitrates[q]].segments[i].unrel_size
      << " loss:" << (uint32_t) (adaptationSet[bitrates[q]].segments[i].unrel_size - client.latest_segment_timing(quic::sst_unrel).received_size_)
      << " @:" << adaptationSet[bitrates[q]].segments[i].mediaRange 
      << " n:" << adaptationSet[bitrates[q]].baseUrl << std::endl;
    

    std::cerr << "[time]"
      << " s:" << std::chrono::duration_cast<std::chrono::milliseconds>(t_req_start - t_start).count()
      << " r:" << std::chrono::duration_cast<std::chrono::milliseconds>(t_rel_stop - t_req_start).count()
      << " u:" << std::chrono::duration_cast<std::chrono::milliseconds>(t_unrel_stop - t_rel_stop).count()
      << " dlr:" << client.latest_segment_timing(quic::sst_rel).time_
      << " dlu:" << client.latest_segment_timing(quic::sst_unrel).time_
      << std::endl;

    std::cerr << "[throughput]"
      << " mavg:"  << t->GetTput()
      << " r:" << client.GetSumThroughput(quic::sst_rel).first
      << " u:" << client.GetSumThroughput(quic::sst_unrel).first
      << std::endl;

    retry = 0;

    auto rel_throughputs = client.all_latest_segment_timing(quic::sst_rel);
    auto unrel_throughputs = client.all_latest_segment_timing(quic::sst_unrel);
    if (!rel_throughputs.empty()) {
      std::cerr << "[rel-throughputs]";
      for (auto &&timing: rel_throughputs) {
        std::cerr << " " << timing.throughput_;
      }
      std::cerr << std::endl;
    }
    if (!unrel_throughputs.empty()) {
      std::cerr << "[unrel-throughputs]";
      for (auto &&timing: unrel_throughputs) {
        std::cerr << " " << timing.throughput_;
      }
      std::cerr << std::endl;
    }

  }

  delete mpc;
  delete bola;
  delete tput;
  //FIXME memory leak of t

  std::cerr << "[done] Terminating" << std::endl;
}
