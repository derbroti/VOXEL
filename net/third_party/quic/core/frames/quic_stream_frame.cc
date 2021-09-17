// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//#define SLST_DEBUG 1

#include <iostream>

#include "net/third_party/quic/core/frames/quic_stream_frame.h"

#include "net/third_party/quic/platform/api/quic_logging.h"

namespace quic {

QuicStreamFrame::QuicStreamFrame() : QuicStreamFrame(0, false, false, 0, nullptr, 0) {
}

QuicStreamFrame::QuicStreamFrame(QuicStreamId stream_id,
                                 bool fin,
                                 bool unreliable,
                                 QuicStreamOffset offset,
                                 QuicStringPiece data)
    : QuicStreamFrame(stream_id, fin, unreliable, offset, data.data(), data.length()) {
    }

QuicStreamFrame::QuicStreamFrame(QuicStreamId stream_id,
                                 bool fin,
                                 bool unreliable,
                                 QuicStreamOffset offset,
                                 QuicPacketLength data_length)
    : QuicStreamFrame(stream_id, fin, unreliable, offset, nullptr, data_length) {
    }

QuicStreamFrame::QuicStreamFrame(QuicStreamId stream_id,
                                 bool fin,
                                 bool unreliable,
                                 QuicStreamOffset offset,
                                 const char* data_buffer,
                                 QuicPacketLength data_length)
    : stream_id(stream_id),
      fin(fin),
      data_length(data_length),
      data_buffer(data_buffer),
      unreliable(unreliable),
      offset(offset),
      receipt_time_(QuicTime::Zero())
      {
#ifdef SLST_DBG
  if (fin || data_length > 0) {
    std::cerr << "QuicStreamFrame(): " << "{ stream_id: " << stream_id
              << ", fin: " << fin << ", offset: " << offset
              << ", length: " << data_length
              << ", reliable: " << !unreliable
              << ", receipt_time: " << receipt_time_.ToDebuggingValue() << " }" << std::endl;
  }
#endif
      }

QuicStreamFrame::~QuicStreamFrame() {}

std::ostream& operator<<(std::ostream& os,
                         const QuicStreamFrame& stream_frame) {
  os << "{ stream_id: " << stream_frame.stream_id
     << ", fin: " << stream_frame.fin << ", offset: " << stream_frame.offset
     << ", length: " << stream_frame.data_length
     << ", reliable: " << !stream_frame.unreliable 
     << ", receipt_time: " << stream_frame.receipt_time_.ToDebuggingValue() << " }\n";
  return os;
}

}  // namespace quic
