
#
# Equivalent to this monstrosity you might see in OpenPgpJS:
#
#  var d = new Date();
#  d = d.getTime()/1000;
#  var timePacket = String.fromCharCode(Math.floor(d/0x1000000%0x100)) + String.fromCharCode(Math.floor(d/0x10000%0x100)) + String.fromCharCode(Math.floor(d/0x100%0x100)) + String.fromCharCode(Math.floor(d%0x100));
#
exports.make_time_packet = (d) ->
  d or= Math.floor(Date.now()/1000)
  b = new Buffer 4
  b.writeUInt32BE d, 0
  b.toString 'binary'

exports.uint_to_buffer = (nbits, i) ->
  ret = null
  switch nbits
    when 16
      ret = new Buffer 2
      ret.writeUInt16BE i, 0
    when 32
      ret = new Buffer 4
      ret.writeUInt32BE i, 0
    when 8
      ret = new Buffer 1
      ret.writeUInt8 i, 0
    else
      throw new Error "Bit types not found: #{nbit}"
  ret