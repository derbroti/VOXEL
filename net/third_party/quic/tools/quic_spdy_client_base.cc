// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//#define SLST_DEBUG 1

#include <chrono>

#include "net/third_party/quic/tools/quic_spdy_client_base.h"

#include "net/third_party/quic/core/crypto/quic_random.h"
#include "net/third_party/quic/core/http/spdy_utils.h"
#include "net/third_party/quic/core/quic_server_id.h"
#include "net/third_party/quic/platform/api/quic_flags.h"
#include "net/third_party/quic/platform/api/quic_logging.h"
#include "net/third_party/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quic/platform/api/quic_text_utils.h"

using base::StringToInt;
using std::string;

namespace quic {

std::pair<double, double> QuicSpdyClientBase::GetSumThroughput(bool unrel) {
  if (segment_timing[unrel].empty()) {
    return {0,0};
  }
  double tp = 0.0;
  double time = 0.0;

  for (auto &i: segment_timing[unrel]) {
    tp += i.throughput_ * (((double) i.time_) / 1000);
    time += ((double) i.time_) / 1000;
  }
  return {tp / time, time};
}

double QuicSpdyClientBase::GetSumThroughput() {
  auto tp_rel = GetSumThroughput(sst_rel);
  auto tp_unrel = GetSumThroughput(sst_unrel);
  if (tp_unrel.first > 0) {
    return (tp_rel.first * tp_rel.second + tp_unrel.first * tp_unrel.second) / (tp_rel.second + tp_unrel.second);
  }
  return tp_rel.first;
}

uint32_t QuicSpdyClientBase::GetSumTime(bool unrel) {
  uint32_t t = 0;

  for (auto &i: segment_timing[unrel]) {
    t += i.time_;
  }
  return t;
}

double QuicSpdyClientBase::GetSumSegmentSize(bool unrel) {
  double ss = 0.0;

  for (auto &i: segment_timing[unrel]) {
    ss += i.segment_size_;
  }
  return ss;
}

double QuicSpdyClientBase::GetSumReceivedSize(bool unrel) {
  double rs = 0.0;

  for (auto &i: segment_timing[unrel]) {
    rs += i.received_size_;
  }
  return rs;
}

void QuicSpdyClientBase::ResetAllTimings() {
  segment_timing[sst_unrel].clear();
  segment_timing[sst_rel].clear();
};

void QuicSpdyClientBase::ClientQuicDataToResend::Resend() {
  client_->SendRequest(*headers_, body_, fin_, unreliable_, fec_);
  headers_ = nullptr;
}

QuicSpdyClientBase::QuicDataToResend::QuicDataToResend(
    std::unique_ptr<spdy::SpdyHeaderBlock> headers,
    QuicStringPiece body,
    bool fin,
    bool unreliable,
    uint8_t fec)
    : headers_(std::move(headers)), body_(body), fin_(fin), unreliable_(unreliable), fec_(fec) {}

QuicSpdyClientBase::QuicDataToResend::~QuicDataToResend() = default;

QuicSpdyClientBase::QuicSpdyClientBase(
    const QuicServerId& server_id,
    const ParsedQuicVersionVector& supported_versions,
    const QuicConfig& config,
    QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory,
    std::unique_ptr<NetworkHelper> network_helper,
    std::unique_ptr<ProofVerifier> proof_verifier)
    : QuicClientBase(server_id,
                     supported_versions,
                     config,
                     helper,
                     alarm_factory,
                     std::move(network_helper),
                     std::move(proof_verifier)),
      store_response_(false),
      latest_response_code_(-1),
      fine_(false) {
      }

QuicSpdyClientBase::~QuicSpdyClientBase() {
  // We own the push promise index. We need to explicitly kill
  // the session before the push promise index goes out of scope.
  ResetSession();
}

QuicSpdyClientSession* QuicSpdyClientBase::client_session() {
  return static_cast<QuicSpdyClientSession*>(QuicClientBase::session());
}

void QuicSpdyClientBase::InitializeSession() {
  client_session()->Initialize();
  client_session()->CryptoConnect();
}


void QuicSpdyClientBase::OnClose(QuicSpdyStream* stream) {
  DCHECK(stream != nullptr);
  QuicSpdyClientStream* client_stream =
      static_cast<QuicSpdyClientStream*>(stream);

  //TODO //FIXME this might not be the ideal position to run the decode...
  /*if (client_stream->get_fec() != 0) {
    client_stream->decode_data();
  }
  */

  const spdy::SpdyHeaderBlock& response_headers =
      client_stream->response_headers();

  if (response_listener_ != nullptr) {
    response_listener_->OnCompleteResponse(stream->id(), response_headers,
                                           client_stream->data());
  }

  // Store response headers and body.
  if (store_response_) {
    auto status = response_headers.find(":status");
    if (status == response_headers.end() ||
        !QuicTextUtils::StringToInt(status->second, &latest_response_code_)) {
      QUIC_LOG(ERROR) << "Invalid response headers";
    }
    latest_response_headers_ = response_headers.DebugString();
    preliminary_response_headers_ =
        client_stream->preliminary_headers().DebugString();
    latest_response_header_block_ = response_headers.Clone();
    latest_response_body_ = client_stream->data();
    latest_response_trailers_ =
        client_stream->received_trailers().DebugString();
    latest_frame_timings_ = client_stream->get_frame_timings();
  }
}

std::unique_ptr<QuicSession> QuicSpdyClientBase::CreateQuicClientSession(
    QuicConnection* connection) {
  return QuicMakeUnique<QuicSpdyClientSession>(*config(), connection,
                                               server_id(), crypto_config(),
                                               &push_promise_index_);
}

QuicSpdyClientStream* QuicSpdyClientBase::SendRequest(const spdy::SpdyHeaderBlock& headers,
                                     QuicStringPiece body,
                                     bool fin,
                                     bool unreliable,
                                     uint8_t fec) {
  QuicClientPushPromiseIndex::TryHandle* handle;
  QuicAsyncStatus rv = push_promise_index()->Try(headers, this, &handle);
  if (rv == QUIC_SUCCESS)
    return nullptr;

  if (rv == QUIC_PENDING) {
    // May need to retry request if asynchronous rendezvous fails.
    AddPromiseDataToResend(headers, body, fin, unreliable, fec);
    return nullptr;
  }

  QuicSpdyClientStream* stream = CreateClientStream(unreliable, fec);
  if (stream == nullptr) {
    QUIC_BUG << "stream creation failed!";
    return nullptr;
  }

  #ifdef SLST_DEBUG 
 std::cout  << "QuicSpdyClientBase::SendRequest: unrel: "<< unreliable << " stream unrel: " << stream->get_unreliable() <<  std::endl; 
 #endif
  
  stream->SendRequest(headers.Clone(), body, fin);

  #ifdef SLST_DEBUG 
 std::cout  << "QuicSpdyClientBase::SendRequest: (after stream->sendrequest) unrel: "<< unreliable << " stream unrel: " << stream->get_unreliable() <<  std::endl; 
 #endif

  // Record this in case we need to resend.
  MaybeAddDataToResend(headers, body, fin, unreliable, fec);

  return stream;
}

void QuicSpdyClientBase::SendRequestAndWaitForResponse(
    const spdy::SpdyHeaderBlock& headers,
    QuicStringPiece body,
    bool fin,
    bool unreliable,
    DownloadConfig *dc) {

  std::vector<SubSegmentTiming>::iterator sstit;
  sstit = segment_timing[unreliable].insert(segment_timing[unreliable].end(), {0,0,0,0,0});
 
  QuicSpdyClientStream *stream = SendRequest(headers, body, fin, unreliable, /*fec*/ 0);

  start_time = std::chrono::system_clock::now();

  stream->ResetReceived();
  Reset();

  if (dc != nullptr) {
    print_helper = dc->size;
  }
  last_received_ = 0;
  idle_time = std::chrono::system_clock::now();
  bola_timer = std::chrono::system_clock::now();
  bola_throughput.clear();
  bpp_moving_average_.Reset();

  while (WaitForEvents(stream, dc, /*idle_check*/ true)) {
  }

  uint32_t time_rough = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start_time).count();


  sstit->received_size_ = 0;
  sstit->time_ = 0;
  if (latest_frame_timings_.empty()) {
    if ((dc != nullptr && dc->ret__kept) || dc == nullptr) {
      std::cerr << "ERROR got no frame/segment_timings - this is not supposed to happen - stopping!" << std::endl;
      exit(-3);
    }
  }

  std::map < quic::QuicStreamOffset, quic::FrameTiming >::iterator quic_frame_it = latest_frame_timings_.begin();
  QuicTime earliest = QuicTime::Zero();
  QuicTime latest = QuicTime::Zero();
  bool earliest_initialized = false;
  for (; quic_frame_it != latest_frame_timings_.end(); ++quic_frame_it) {
    sstit->received_size_ += (quic_frame_it->second.was_lost) ? 0 : quic_frame_it->second.length;
    if (!earliest_initialized || quic_frame_it->second.qt < earliest) {
      earliest = quic_frame_it->second.qt;
      earliest_initialized = true;
    }
    if (quic_frame_it->second.qt > latest) {
      latest = quic_frame_it->second.qt;
    }
  }
  sstit->time_ = (latest - earliest).ToMilliseconds();
  // if for whatever reason this time is below 1ms, round up to 1ms
  sstit->time_rough_ = (!time_rough)?1:time_rough;

  if (!fine_) {
    sstit->time_ = time_rough;
    sstit->throughput_ = (latest_response_body_.size() * 8) / sstit->time_;
  } else {
    // Time measured was below 1 ms.
    if (sstit->time_ == 0) {
      sstit->time_ = 1;
    }
    sstit->throughput_ = (sstit->received_size_ * 8) / sstit->time_;
  }
  sstit->segment_size_ = latest_response_body_.size();
}

void QuicSpdyClientBase::SendRequestAndWaitForResponse(
    const spdy::SpdyHeaderBlock& headers,
    QuicStringPiece body,
    bool fin,
    bool unreliable) {
    SendRequestAndWaitForResponse(headers, body, fin, unreliable, NULL);
}  


void QuicSpdyClientBase::SendRequestsAndWaitForResponse(
    const std::vector<string>& url_list) {
  for (size_t i = 0; i < url_list.size(); ++i) {
    spdy::SpdyHeaderBlock headers;
    if (!SpdyUtils::PopulateHeaderBlockFromUrl(url_list[i], &headers)) {
      QUIC_BUG << "Unable to create request";
      continue;
    }
    std::cerr << "NOT IMPLEMENTED" << std::endl;
    exit(-1);
    SendRequest(headers, "", true, /*unrel*/false, /*fec*/0);
  }
  /*while (WaitForEvents()) {
  }
  */
}

QuicSpdyClientStream* QuicSpdyClientBase::CreateClientStream(bool unreliable, uint8_t fec) {
  if (!connected()) {
    std::cout << "CreateClientStream: NOT CONNECTED" << std::endl;
    return nullptr;
  }

  auto* stream = static_cast<QuicSpdyClientStream*>(
      client_session()->CreateOutgoingDynamicStream());
  if (stream) {
    stream->SetPriority(QuicStream::kDefaultPriority);
    stream->set_visitor(this);
    stream->set_unreliable(unreliable);
    stream->set_fec(fec);
  }

  #ifdef SLST_DEBUG 
 std::cout  << "CreateClientStream: id: " << stream->id() << " unrel: " << stream->get_unreliable() <<  std::endl; 
 #endif

  return stream;
}

int QuicSpdyClientBase::GetNumSentClientHellosFromSession() {
  return client_session()->GetNumSentClientHellos();
}

int QuicSpdyClientBase::GetNumReceivedServerConfigUpdatesFromSession() {
  return client_session()->GetNumReceivedServerConfigUpdates();
}

void QuicSpdyClientBase::MaybeAddDataToResend(
    const spdy::SpdyHeaderBlock& headers,
    QuicStringPiece body,
    bool fin,
    bool unreliable,
    uint8_t fec) {
  if (!GetQuicReloadableFlag(enable_quic_stateless_reject_support)) {
    return;
  }

  if (client_session()->IsCryptoHandshakeConfirmed()) {
    // The handshake is confirmed.  No need to continue saving requests to
    // resend.
    data_to_resend_on_connect_.clear();
    return;
  }

  // The handshake is not confirmed.  Push the data onto the queue of data to
  // resend if statelessly rejected.
  std::unique_ptr<spdy::SpdyHeaderBlock> new_headers(
      new spdy::SpdyHeaderBlock(headers.Clone()));
  std::unique_ptr<QuicDataToResend> data_to_resend(
      new ClientQuicDataToResend(std::move(new_headers), body, fin, unreliable, fec, this));
  MaybeAddQuicDataToResend(std::move(data_to_resend));
}

void QuicSpdyClientBase::MaybeAddQuicDataToResend(
    std::unique_ptr<QuicDataToResend> data_to_resend) {
  data_to_resend_on_connect_.push_back(std::move(data_to_resend));
}

void QuicSpdyClientBase::ClearDataToResend() {
  data_to_resend_on_connect_.clear();
}

void QuicSpdyClientBase::ResendSavedData() {
  // Calling Resend will re-enqueue the data, so swap out
  //  data_to_resend_on_connect_ before iterating.
  std::vector<std::unique_ptr<QuicDataToResend>> old_data;
  old_data.swap(data_to_resend_on_connect_);
  for (const auto& data : old_data) {
    data->Resend();
  }
}

void QuicSpdyClientBase::AddPromiseDataToResend(
    const spdy::SpdyHeaderBlock& headers,
    QuicStringPiece body,
    bool fin,
    bool unreliable,
    uint8_t fec) {
  std::unique_ptr<spdy::SpdyHeaderBlock> new_headers(
      new spdy::SpdyHeaderBlock(headers.Clone()));
  push_promise_data_to_resend_.reset(
      new ClientQuicDataToResend(std::move(new_headers), body, fin, unreliable, fec, this));
}

bool QuicSpdyClientBase::CheckVary(
    const spdy::SpdyHeaderBlock& client_request,
    const spdy::SpdyHeaderBlock& promise_request,
    const spdy::SpdyHeaderBlock& promise_response) {
  return true;
}

void QuicSpdyClientBase::OnRendezvousResult(QuicSpdyStream* stream) {
  std::unique_ptr<ClientQuicDataToResend> data_to_resend =
      std::move(push_promise_data_to_resend_);
  if (stream) {
    stream->set_visitor(this);
    stream->OnDataAvailable();
  } else if (data_to_resend) {
    data_to_resend->Resend();
  }
}

size_t QuicSpdyClientBase::latest_response_code() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_code_;
}

const string& QuicSpdyClientBase::latest_response_headers() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_headers_;
}

const string& QuicSpdyClientBase::preliminary_response_headers() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return preliminary_response_headers_;
}

const spdy::SpdyHeaderBlock& QuicSpdyClientBase::latest_response_header_block() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_header_block_;
}

const string& QuicSpdyClientBase::latest_response_body() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_body_;
}

const std::map < QuicStreamOffset, FrameTiming >& QuicSpdyClientBase::latest_response_timings() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_frame_timings_;
}

const SubSegmentTiming QuicSpdyClientBase::latest_segment_timing(bool unrel) const {
  if (segment_timing[unrel].empty()) {
    return {0, 0, 0, 0, 0};
  }
  return segment_timing[unrel].back();
}

const string& QuicSpdyClientBase::latest_response_trailers() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_trailers_;
}

}  // namespace quic
