
ukm = require './ukm'
{make_esc} = require 'iced-error'
{promisify} = require 'util'

exports.GenericKey = class GenericKey
  constructor : ({@km}) ->
  kid : () -> @km.get_ekid().toString('hex')
  isPGP : () -> !!@km.get_pgp_fingerprint()
  _verify_cb : (s, opts, cb) ->
    esc = make_esc cb
    sig_eng = @km.make_sig_eng()
    await sig_eng.unbox s, esc(defer(payload, body)), opts
    cb null, [payload, body]
  verify : (s, opts) -> promisify(@_verify_cb.bind(@))(s, opts)

import_key_cb = (s, opts, cb) ->
  esc = make_esc cb
  await ukm.import_armored_public { armored : s, opts }, esc defer km
  ret = new GenericKey { km }
  cb null, ret

exports.importKey = promisify(import_key_cb)
