// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <chrono>
#include "net/third_party/quic/tools/quic_client_base.h"

#include "net/third_party/quic/core/crypto/quic_random.h"
#include "net/third_party/quic/core/http/spdy_utils.h"
#include "net/third_party/quic/core/quic_server_id.h"
#include "net/third_party/quic/core/tls_client_handshaker.h"
#include "net/third_party/quic/platform/api/quic_flags.h"
#include "net/third_party/quic/platform/api/quic_logging.h"
#include "net/third_party/quic/platform/api/quic_text_utils.h"
#include "net/third_party/quic/tools/quic_spdy_client_base.h"
#include "quic_client_base.h"

using base::StringToInt;
using std::string;

std::unordered_map<std::string,std::string> feature_map;

namespace quic {


QuicClientBase::NetworkHelper::~NetworkHelper() = default;

QuicClientBase::QuicClientBase(
    const QuicServerId& server_id,
    const ParsedQuicVersionVector& supported_versions,
    const QuicConfig& config,
    QuicConnectionHelperInterface* helper,
    QuicAlarmFactory* alarm_factory,
    std::unique_ptr<NetworkHelper> network_helper,
    std::unique_ptr<ProofVerifier> proof_verifier)
    : server_id_(server_id),
      initialized_(false),
      local_port_(0),
      config_(config),
      crypto_config_(std::move(proof_verifier),
                     TlsClientHandshaker::CreateSslCtx()),
      helper_(helper),
      alarm_factory_(alarm_factory),
      supported_versions_(supported_versions),
      initial_max_packet_length_(0),
      num_stateless_rejects_received_(0),
      num_sent_client_hellos_(0),
      connection_error_(QUIC_NO_ERROR),
      connected_or_attempting_connect_(false),
      network_helper_(std::move(network_helper)) {}

QuicClientBase::~QuicClientBase() = default;

bool QuicClientBase::Initialize() {
  num_sent_client_hellos_ = 0;
  num_stateless_rejects_received_ = 0;
  connection_error_ = QUIC_NO_ERROR;
  connected_or_attempting_connect_ = false;

  // If an initial flow control window has not explicitly been set, then use the
  // same values that Chrome uses.
  const uint32_t kSessionMaxRecvWindowSize = 15 * 1024 * 1024;  // 15 MB
  const uint32_t kStreamMaxRecvWindowSize = 6 * 1024 * 1024;    //  6 MB
  if (config()->GetInitialStreamFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config()->SetInitialStreamFlowControlWindowToSend(kStreamMaxRecvWindowSize);
  }
  if (config()->GetInitialSessionFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config()->SetInitialSessionFlowControlWindowToSend(
        kSessionMaxRecvWindowSize);
  }

  if (!network_helper_->CreateUDPSocketAndBind(server_address_,
                                               bind_to_address_, local_port_)) {
    return false;
  }

  initialized_ = true;
  return true;
}

bool QuicClientBase::Connect() {
  // Attempt multiple connects until the maximum number of client hellos have
  // been sent.
  while (!connected() &&
         GetNumSentClientHellos() <= QuicCryptoClientStream::kMaxClientHellos) {
    StartConnect();
    while (EncryptionBeingEstablished()) {
      WaitForEvents(nullptr, nullptr);
    }
    if (GetQuicReloadableFlag(enable_quic_stateless_reject_support) &&
        connected()) {
      // Resend any previously queued data.
      ResendSavedData();
    }
    if (session() != nullptr &&
        session()->error() != QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
      // We've successfully created a session but we're not connected, and there
      // is no stateless reject to recover from.  Give up trying.
      break;
    }
  }
  if (!connected() &&
      GetNumSentClientHellos() > QuicCryptoClientStream::kMaxClientHellos &&
      session() != nullptr &&
      session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    // The overall connection failed due too many stateless rejects.
    set_connection_error(QUIC_CRYPTO_TOO_MANY_REJECTS);
  }
  return session()->connection()->connected();
}

void QuicClientBase::StartConnect() {
  DCHECK(initialized_);
  DCHECK(!connected());
  QuicPacketWriter* writer = network_helper_->CreateQuicPacketWriter();
  if (connected_or_attempting_connect()) {
    // If the last error was not a stateless reject, then the queued up data
    // does not need to be resent.
    if (session()->error() != QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
      ClearDataToResend();
    }
    // Before we destroy the last session and create a new one, gather its stats
    // and update the stats for the overall connection.
    UpdateStats();
  }

  session_ = CreateQuicClientSession(new QuicConnection(
      GetNextConnectionId(), server_address(), helper(), alarm_factory(),
      writer,
      /* owns_writer= */ false, Perspective::IS_CLIENT, supported_versions()));
  if (initial_max_packet_length_ != 0) {
    session()->connection()->SetMaxPacketLength(initial_max_packet_length_);
  }
  // Reset |writer()| after |session()| so that the old writer outlives the old
  // session.
  set_writer(writer);
  InitializeSession();
  set_connected_or_attempting_connect(true);
}

void QuicClientBase::InitializeSession() {
  session()->Initialize();
}

void QuicClientBase::Disconnect() {
  DCHECK(initialized_);

  initialized_ = false;
  if (connected()) {
    session()->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Client disconnecting",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }

  ClearDataToResend();

  network_helper_->CleanUpAllUDPSockets();
}

ProofVerifier* QuicClientBase::proof_verifier() const {
  return crypto_config_.proof_verifier();
}

bool QuicClientBase::EncryptionBeingEstablished() {
  return !session_->IsEncryptionEstablished() &&
         session_->connection()->connected();
}

bool QuicClientBase::WaitForEvents(QuicSpdyClientStream* stream, DownloadConfig *dc) {
  return WaitForEvents(stream, dc, /*idle_check*/false);
}

void QuicClientBase::Reset() {
  remaining_time = 0;
  remaining_size = 0;
  lossy_remaining_size = 0;
  rem_dl_time = 0;
  rem_fb_time = 0;
  target_time = 0;
  current_throughput = 0;
  calculated_threshold = 0;
}

const double ABANDON_MULTIPLIER = 1.8;
const int GRACE_TIME_THRESHOLD = 500;
const int MIN_LENGTH_TO_AVERAGE = 5;
const double kBandwidthSafetyFactor = 0.9;

bool QuicClientBase::bola_shouldAbandon(size_t received, int32_t time, DownloadConfig *dc) {
  
  if (dc->buffer_occ > 12000) {
    return false;
  }
  bola_throughput.push_back(received * 8 / time);

  if (bola_throughput.size() >= MIN_LENGTH_TO_AVERAGE && time > GRACE_TIME_THRESHOLD && received < dc->size) {

    double totalSampledValue = accumulate(bola_throughput.begin(), bola_throughput.end(), 0);
    double measuredBandwidthInKbps = std::round(totalSampledValue / bola_throughput.size());
    // bit / kbps = ks = ms == size * 8 / 1000 * 1000
    double estimatedTimeOfDownload = dc->size * 8 / measuredBandwidthInKbps;
    if (estimatedTimeOfDownload < dc->segment_duration * ABANDON_MULTIPLIER || dc->quality == 0 ) {
        return false;
    } else {
        BolaAbr *bola = (BolaAbr*) (dc->abr_instance);
        size_t bytesRemaining = dc->size - received;
        // TODO-Jan25: Pass information instead of placeholder kInProgress
        dc->ret__quality = bola->BolaE(dc->buffer_occ, measuredBandwidthInKbps * kBandwidthSafetyFactor, &(dc->ret__pause), /*retry*/0, kInProgress);

        size_t estimateOtherBytesTotal = dc->size * dc->bitrates[dc->ret__quality] / dc->bitrates[dc->quality];
        if (bytesRemaining > estimateOtherBytesTotal) {
            return true;
        }
    }
  }

  return false;
}

bool QuicClientBase::DeadlineRequest() {
  return target_time <= 0;
}


bool QuicClientBase::BPPShouldAbandon(size_t received, int32_t time, DownloadConfig *dc) {
  bpp_moving_average_.AddMeasurement(received, time);

  if (time > GRACE_TIME_THRESHOLD && received < dc->size) {
    double measuredBandwidthInKbps = bpp_moving_average_.GetThroughput();
    if (measuredBandwidthInKbps == 0) {
      return false;
    }
    // bit / kbps = ks = ms == size * 8 / 1000 * 1000
    double estimatedRemainingDownloadTime = (dc->size - received) * 8 / measuredBandwidthInKbps;
    uint32_t remaining_buffer = dc->buffer_occ - time;
    if (estimatedRemainingDownloadTime < remaining_buffer) {
      return false;
    }
    if (dc->quality > 0) {
      BolaAbr *bola = (BolaAbr*) (dc->abr_instance);
      // TODO: replace 0.0 with SSIM - 0.0 is just "old" behavior
      DownloadProgress dp = {true, dc->quality, 0.0, dc->size, received, dc->reliable};
      dc->ret__ssim = bola->BolaE(remaining_buffer, measuredBandwidthInKbps * kBandwidthSafetyFactor, *(dc->ssim_map), &(dc->ret__pause), /*retry*/0, dp);
      auto &ssim_q = (*(dc->ssim_map))[dc->ret__ssim];
      dc->ret__quality = ssim_q.quality;
      if (dc->ret__quality < dc->quality) {
        return true;
      } else if (!dc->reliable && dc->ret__quality == dc->quality && received >= ssim_q.size) {
        dc->ret__kept = true;
        return true;
      }
    }
  }
  return false;
}

bool QuicClientBase::BPPRequest(QuicSpdyClientStream* stream, DownloadConfig *dc, uint32_t time) {
  uint32_t timer = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now() - bola_timer).count();
  //if (timer >= 50 || stream->GetTime() > last_stream_time) {
  if (timer >= 50) {
    bola_timer = std::chrono::system_clock::now();
    last_stream_time = stream->GetTime();
    return BPPShouldAbandon(stream->GetReceived(/*lossy=*/false), time, dc);
  }
  return false;
}

bool QuicClientBase::BolaRequest(QuicSpdyClientStream* stream, DownloadConfig *dc, uint32_t time) {
  uint32_t timer = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now() - bola_timer).count();
  if (timer >= 50) {
    bool cancel = bola_shouldAbandon(stream->GetReceived(/*lossy=*/false), time, dc);
    bola_timer = std::chrono::system_clock::now();
    return cancel;
  }
  return false;
}

bool QuicClientBase::EnhancedBolaRequest(QuicSpdyClientStream* stream, DownloadConfig *dc, uint32_t time) {
  uint32_t timer = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now() - bola_timer).count();
  //if (timer >= 50 || stream->GetTime() > last_stream_time) {
  if (timer >= 50) {
    bola_timer = std::chrono::system_clock::now();
    last_stream_time = stream->GetTime();
    return EnhancedBolaShouldAbandon(stream->GetReceived(/*lossy=*/false), time, dc);
  }
  return false;
}

bool QuicClientBase::EnhancedBolaShouldAbandon(size_t received, int32_t time, DownloadConfig *dc) {

  bola_throughput.push_back(received * 8 / time);

  if (bola_throughput.size() >= MIN_LENGTH_TO_AVERAGE && time > GRACE_TIME_THRESHOLD && received < dc->size) {

    double totalSampledValue = accumulate(bola_throughput.begin(), bola_throughput.end(), 0);
    double measuredBandwidthInKbps = std::round(totalSampledValue / bola_throughput.size());
    // bit / kbps = ks = ms == size * 8 / 1000 * 1000
    double estimatedTimeOfDownload = dc->size * 8 / measuredBandwidthInKbps;
    if (estimatedTimeOfDownload < dc->segment_duration * ABANDON_MULTIPLIER || dc->quality == 0 ) {
      return false;
    } else {
      BolaAbr *bola = (BolaAbr*) (dc->abr_instance);
      size_t bytesRemaining = dc->size - received;
      std::vector<double> segment_sizes_bits;
      for (auto &bitrate : dc->bitrates) {
        segment_sizes_bits.push_back((*(dc->adaptationSet))[bitrate].segments[dc->segment_no].size * 8);
      }
      // TODO-Jan25: Update with ssim_map
      // TODO-Jan25: Pass information instead of placeholder kInProgress
      dc->ret__quality = bola->BolaE(dc->buffer_occ - time, measuredBandwidthInKbps * kBandwidthSafetyFactor, segment_sizes_bits, &(dc->ret__pause), /*retry*/0, kInProgress);
      size_t otherBytesTotal = (*(dc->adaptationSet))[dc->bitrates[dc->ret__quality]].segments[dc->segment_no].size;
      if (bytesRemaining > otherBytesTotal) {
        return true;
      }
    }
  }

  return false;
}

bool QuicClientBase::WaitForEvents(QuicSpdyClientStream* stream, DownloadConfig *dc, bool idle_check) {
  DCHECK(connected());

  network_helper_->RunEventLoop();

  DCHECK(session() != nullptr);
  if (!connected() &&
      session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    DCHECK(GetQuicReloadableFlag(enable_quic_stateless_reject_support));
    QUIC_DLOG(INFO) << "Detected stateless reject while waiting for events.  "
                    << "Attempting to reconnect.";
    Connect();
  }


  bool done = session()->num_active_requests() == 0;

  uint32_t time_delta = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start_time).count();

  ////
  // IDLE CHECK - HACK
  if (stream != nullptr && idle_check) {
    uint32_t idle = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - idle_time).count();

    size_t recv = stream->GetReceived(/*lossy=*/false);

    if (last_received_ == recv && idle > 15000) {
      std::cerr << "[idle] " << idle << std::endl;
      idle_time = std::chrono::system_clock::now();
    } else {
      last_received_ = recv;
      idle_time = std::chrono::system_clock::now();
    }
  }
  ////

  if (stream != nullptr && dc != nullptr && !done) {
    remaining_time = dc->buffer_occ - time_delta;
    remaining_size = dc->size - stream->GetReceived(/*lossy=*/false);
    lossy_remaining_size = dc->size - stream->GetReceived(/*lossy=*/true);
    current_throughput = stream->GetThroughput();
    if (current_throughput != 0) {
      rem_dl_time = ((lossy_remaining_size / 1000) / (current_throughput / 8)) * 1000;
      rem_fb_time = ((dc->fallback_size / 1000) / (current_throughput / 8)) * 1000;
    }
    target_time = remaining_time - kSafetyMargin;
    calculated_threshold = (dc->size - lossy_remaining_size) / (float) dc->size;
    bool cancel = false;
    if (dc->abr == "bpp") {
      cancel = BPPRequest(stream, dc, time_delta);
    } else if (dc->abr == "bola") {
      if (feature_map.find("bola_enhanced") != feature_map.end()) {
        cancel = EnhancedBolaRequest(stream, dc, time_delta);
      } else {
        cancel = BolaRequest(stream, dc, time_delta);
      }
    } else if (dc->abr == "deadline") {
      cancel = DeadlineRequest();
      // We may cancel before we receive anything, so only set keep to true if we have at least something, else we might
      // not even have received headers.
      if (stream->GetReceived(/*lossy=*/false) > 0) {
        dc->ret__kept = true;
      }
    }
    if (cancel) {
      stream->Reset(QUIC_STREAM_NO_ERROR);
      ((QuicSpdyClientBase *) dc->client)->OnClose(stream);
      while (session()->num_active_requests() != 0) {
        network_helper_->RunEventLoop();
      }
      std::cerr << "[cancel-reason]"
                << " rel:" << dc->reliable
                << " t:" << time_delta
                << " rs:" << remaining_size
                << " lrs:" << lossy_remaining_size
                << " rt:" << rem_dl_time
                << " rft:" << rem_fb_time
                << " buf:" << target_time
                << " keep:" << dc->ret__kept
                << " cthrsh:" << calculated_threshold
                << std::endl;
      // done = true
      return false;
    }

    if (print_helper >= 50000 && lossy_remaining_size < (unsigned long) (print_helper) - 50000) {
      std::cerr << "[cancel-try]"
                << " rel:" << dc->reliable
                << " t:" << time_delta
                << " rs:" << remaining_size
                << " lrs:" << lossy_remaining_size
                << " rt:" << rem_dl_time
                << " rft:" << rem_fb_time
                << " buf:" << target_time
                << " keep:" << dc->ret__kept
                << " tp:" << current_throughput
                << std::endl;
      print_helper = lossy_remaining_size;
    }
  }

  if (stream && done) {
    if (dc != nullptr) {
      dc->ret__kept = true;
      std::cerr << "[cancel-fin]"
                << " rel:" << dc->reliable
                << " t:" << time_delta
                << " rs:" << remaining_size
                << " lrs:" << lossy_remaining_size
                << " rt:" << rem_dl_time
                << " rft:" << rem_fb_time
                << " buf:" << target_time
                << " keep:" << dc->ret__kept
                << std::endl;
    } else {
      std::cerr << "[cancel-fin] t:" << time_delta << std::endl;
    }
  }

  // return false when done for callers while loop
  return !done;
}

bool QuicClientBase::MigrateSocket(const QuicIpAddress& new_host) {
  return MigrateSocketWithSpecifiedPort(new_host, local_port_);
}

bool QuicClientBase::MigrateSocketWithSpecifiedPort(
    const QuicIpAddress& new_host,
    int port) {
  if (!connected()) {
    return false;
  }

  network_helper_->CleanUpAllUDPSockets();

  set_bind_to_address(new_host);
  if (!network_helper_->CreateUDPSocketAndBind(server_address_,
                                               bind_to_address_, port)) {
    return false;
  }

  session()->connection()->SetSelfAddress(
      network_helper_->GetLatestClientAddress());

  QuicPacketWriter* writer = network_helper_->CreateQuicPacketWriter();
  set_writer(writer);
  session()->connection()->SetQuicPacketWriter(writer, false);

  return true;
}

QuicSession* QuicClientBase::session() {
  return session_.get();
}

QuicClientBase::NetworkHelper* QuicClientBase::network_helper() {
  return network_helper_.get();
}

const QuicClientBase::NetworkHelper* QuicClientBase::network_helper() const {
  return network_helper_.get();
}

void QuicClientBase::WaitForStreamToClose(QuicStreamId id) {
  DCHECK(connected());

  while (connected() && !session_->IsClosedStream(id)) {
    WaitForEvents(nullptr, nullptr);
  }
}

bool QuicClientBase::WaitForCryptoHandshakeConfirmed() {
  DCHECK(connected());

  while (connected() && !session_->IsCryptoHandshakeConfirmed()) {
    WaitForEvents(nullptr, nullptr);
  }

  // If the handshake fails due to a timeout, the connection will be closed.
  QUIC_LOG_IF(ERROR, !connected()) << "Handshake with server failed.";
  return connected();
}

bool QuicClientBase::connected() const {
  return session_.get() && session_->connection() &&
         session_->connection()->connected();
}

bool QuicClientBase::goaway_received() const {
  return session_ != nullptr && session_->goaway_received();
}

int QuicClientBase::GetNumSentClientHellos() {
  // If we are not actively attempting to connect, the session object
  // corresponds to the previous connection and should not be used.
  const int current_session_hellos = !connected_or_attempting_connect_
                                         ? 0
                                         : GetNumSentClientHellosFromSession();
  return num_sent_client_hellos_ + current_session_hellos;
}

void QuicClientBase::UpdateStats() {
  num_sent_client_hellos_ += GetNumSentClientHellosFromSession();
  if (session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    ++num_stateless_rejects_received_;
  }
}

int QuicClientBase::GetNumReceivedServerConfigUpdates() {
  // If we are not actively attempting to connect, the session object
  // corresponds to the previous connection and should not be used.
  // We do not need to take stateless rejects into account, since we
  // don't expect any scup messages to be sent during a
  // statelessly-rejected connection.
  return !connected_or_attempting_connect_
             ? 0
             : GetNumReceivedServerConfigUpdatesFromSession();
}

QuicErrorCode QuicClientBase::connection_error() const {
  // Return the high-level error if there was one.  Otherwise, return the
  // connection error from the last session.
  if (connection_error_ != QUIC_NO_ERROR) {
    return connection_error_;
  }
  if (session_ == nullptr) {
    return QUIC_NO_ERROR;
  }
  return session_->error();
}

QuicConnectionId QuicClientBase::GetNextConnectionId() {
  QuicConnectionId server_designated_id = GetNextServerDesignatedConnectionId();
  return server_designated_id ? server_designated_id
                              : GenerateNewConnectionId();
}

QuicConnectionId QuicClientBase::GetNextServerDesignatedConnectionId() {
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config_.LookupOrCreate(server_id_);
  // If the cached state indicates that we should use a server-designated
  // connection ID, then return that connection ID.
  CHECK(cached != nullptr) << "QuicClientCryptoConfig::LookupOrCreate returned "
                           << "unexpected nullptr.";
  return cached->has_server_designated_connection_id()
             ? cached->GetNextServerDesignatedConnectionId()
             : 0;
}

QuicConnectionId QuicClientBase::GenerateNewConnectionId() {
  return QuicRandom::GetInstance()->RandUint64();
}

}  // namespace quic
