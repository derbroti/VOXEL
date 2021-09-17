// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//#define SLST_DEBUG 1

#include "net/third_party/quic/core/http/quic_spdy_client_stream.h"

#include <utility>
#include <iostream>
#include <thread>

#include "net/third_party/quic/core/http/quic_client_promised_info.h"
#include "net/third_party/quic/core/http/quic_spdy_client_session.h"
#include "net/third_party/quic/core/http/spdy_utils.h"
#include "net/third_party/quic/core/quic_alarm.h"
#include "net/third_party/quic/platform/api/quic_logging.h"
#include "net/third_party/spdy/core/spdy_protocol.h"


using spdy::SpdyHeaderBlock;

namespace quic {

QuicSpdyClientStream::QuicSpdyClientStream(QuicStreamId id,
                                           QuicSpdyClientSession* session)
    : QuicSpdyStream(id, session),
      content_length_(-1),
      response_code_(0),
      header_bytes_read_(0),
      header_bytes_written_(0),
      session_(session),
      has_preliminary_headers_(false) {}

QuicSpdyClientStream::~QuicSpdyClientStream() = default;



std::map < QuicStreamOffset, FrameTiming >& QuicSpdyClientStream::get_frame_timings() {
  return sequencer()->get_frame_timings();
}

void QuicSpdyClientStream::OnInitialHeadersComplete(
    bool fin,
    bool unreliable,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, unreliable, frame_len, header_list);

  DCHECK(headers_decompressed());
  header_bytes_read_ += frame_len;
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &content_length_,
                                         &response_headers_)) {
    QUIC_DLOG(ERROR) << "Failed to parse header list: "
                     << header_list.DebugString();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  if (!ParseHeaderStatusCode(response_headers_, &response_code_)) {
    QUIC_DLOG(ERROR) << "Received invalid response code: "
                     << response_headers_[":status"].as_string();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  if (response_code_ == 100 && !has_preliminary_headers_) {
    // These are preliminary 100 Continue headers, not the actual response
    // headers.
    set_headers_decompressed(false);
    has_preliminary_headers_ = true;
    preliminary_headers_ = std::move(response_headers_);
  }

  ConsumeHeaderList();
  QUIC_DVLOG(1) << "headers complete for stream " << id();

  session_->OnInitialHeadersComplete(id(), response_headers_);
}

void QuicSpdyClientStream::OnTrailingHeadersComplete(
    bool fin,
    bool unreliable,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnTrailingHeadersComplete(fin, unreliable, frame_len, header_list);
  MarkTrailersConsumed();
}

void QuicSpdyClientStream::OnPromiseHeaderList(
    QuicStreamId promised_id,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  header_bytes_read_ += frame_len;
  int64_t content_length = -1;
  SpdyHeaderBlock promise_headers;
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &content_length,
                                         &promise_headers)) {
    QUIC_DLOG(ERROR) << "Failed to parse promise headers: "
                     << header_list.DebugString();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  session_->HandlePromised(id(), promised_id, promise_headers);
  if (visitor() != nullptr) {
    visitor()->OnPromiseHeadersComplete(promised_id, frame_len);
  }
}

void QuicSpdyClientStream::decode_data() {
/*
  if (get_fec() != 0) {
    std::cerr << "de-fec'ing: " << (int)(get_fec()) << " old len: " << data_.length();
    ezpwd::RS<255, 170> rs;

    std::string chunk = "", decoded = "";

    for (unsigned long i = 0; i < data_.length() / 340; ++i) {
      chunk = data_.substr(i*255, 255);
      int fixed = rs.decode(chunk);
      if (fixed < 0)
        std::cerr << "decoding failed" << std::endl;

      chunk.resize( chunk.size() - rs.nroots() );
      decoded += chunk;
    }

    content_length_ = decoded.length();

    std::cerr << " new len: " << decoded.length() << std::endl;
  }
*/
}

void QuicSpdyClientStream::OnDataAvailable() {
  #ifdef SLST_DEBUG 
 std::cout  << "OnDataAvailable called" <<  std::endl; 
 #endif
  // For push streams, visitor will not be set until the rendezvous
  // between server promise and client request is complete.
  if (visitor() == nullptr)
    return;

  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    #ifdef SLST_DEBUG 
 std::cout  << "Client processed " << iov.iov_len << " bytes for stream "
                  << id();

    #endif

    if (iov.iov_base != NULL)
    {
      #ifdef SLST_DEBUG 
      std::cout <<  "\n" << data_.length() << " | " << iov.iov_len <<  std::endl; 
      #endif
 
      data_.append(static_cast<char*>(iov.iov_base), iov.iov_len);
    }
    else
    {
      #ifdef SLST_DEBUG 
 std::cout  << "NOTE: no data_ ?! in OnDataAvailable() call" <<  std::endl; 
 #endif
    }

    if (content_length_ >= 0 &&
        data_.size() > static_cast<uint64_t>(content_length_)) {
      QUIC_DLOG(ERROR) << "Invalid content length (" << content_length_
                       << ") with data of size " << data_.size();
      Reset(QUIC_BAD_APPLICATION_PAYLOAD);
      return;
    }
    MarkConsumed(iov.iov_len);
  }
  //std::cout << "A qscs-OnDataAvailable: seq: " << sequencer()->IsClosed() << std::endl;

  if (sequencer()->IsClosed()) {
    #ifdef SLST_DEBUG 
    std::cout << "B qscs-OnDataAvailable: seq: " << sequencer()->IsClosed() << std::endl;
    #endif
    OnFinRead();
  } else {
    sequencer()->SetUnblocked();
  }
}

size_t QuicSpdyClientStream::SendRequest(SpdyHeaderBlock headers,
                                         QuicStringPiece body,
                                         bool fin) {
  #ifdef SLST_DEBUG 
 std::cout  << "1SendRequest am i unreliable?: " << this->unreliable_  << " this: " << this << " id: " << id() <<  std::endl; 
 #endif

  QuicConnection::ScopedPacketFlusher flusher(
      session_->connection(), QuicConnection::SEND_ACK_IF_QUEUED);

  #ifdef SLST_DEBUG 
 std::cout  << "2SendRequest am i unreliable?: " << this->unreliable_ << " this: " << this <<  std::endl; 
 #endif

  bool send_fin_with_headers = fin && body.empty();
  size_t bytes_sent = body.size();

  #ifdef SLST_DEBUG 
 std::cout  << "3SendRequest am i unreliable?: " << this->unreliable_ << " this: " << this <<  std::endl; 
 #endif

  #ifdef SLST_DEBUG 
 std::cout  << "SendRequest id: " << id() << " unrel: " << this->unreliable_ << " this: " << this << " tid: " << std::this_thread::get_id() <<  std::endl; 
 #endif

  headers["x-slipstream-unreliable"] = (this->unreliable_)?std::string("true"):std::string("false");
  headers["x-slipstream-fec"] = (this->unreliable_)?std::string("170"):std::string("0");


  header_bytes_written_ =
      WriteHeaders(std::move(headers), send_fin_with_headers, nullptr);
  bytes_sent += header_bytes_written_;

  #ifdef SLST_DEBUG 
 std::cout  << "4SendRequest am i unreliable?: " << this->unreliable_ << " this: " << this <<  std::endl; 
 #endif

  if (!body.empty()) {
    WriteOrBufferData(body, fin, nullptr);
  }
  #ifdef SLST_DEBUG 
 std::cout  << "5SendRequest am i unreliable?: " << this->unreliable_ << " this: " << this <<  std::endl; 
 #endif

  return bytes_sent;
}

}  // namespace quic
