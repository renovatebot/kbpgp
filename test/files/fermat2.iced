
{small_primes,nbs,fermat2_test} = require '../../src/prime'
{nbv} = require('openpgp').bigint

exports.test_small_primes = (T, cb) ->
  for p in small_primes
    T.assert fermat2_test(nbv(p)), "Prime #{p}"
  cb()

exports.test_small_composites = (T,cb) ->
  for p in small_primes
    T.assert not(fermat2_test(nbv(p).add(nbv(3)))), "Composite #{p} + 3"
  cb()

exports.test_charmichael_numbers = (T,cb) ->
  C = [ "561",
        "41041",
        "825265",
        "321197185",
        "5394826801",
        "232250619601",
        "9746347772161",
        "1436697831295441",
        "60977817398996785",
        "7156857700403137441",
        "1791562810662585767521",
        "87674969936234821377601",
        "6553130926752006031481761",
        "1590231231043178376951698401",
        "35237869211718889547310642241",
        "32809426840359564991177172754241",
        "2810864562635368426005268142616001",
        "349407515342287435050603204719587201",
        "125861887849639969847638681038680787361",
        "12758106140074522771498516740500829830401"  ]
  for c in C
    T.assert fermat2_test(nbs(c)), "Charmichael # #{c}"
  cb()

exports.test_larger_primes = (T,cb) ->
  P = [ "282755483533707287054752184321121345766861480697448703443857012153264407439766013042402571",
        "370332600450952648802345609908335058273399487356359263038584017827194636172568988257769601", 
        "463199005416013829210323411514132845972525641604435693287586851332821637442813833942427923",
        "374413471625854958269706803072259202131399386829497836277471117216044734280924224462969371",
        "664869143773196608462001772779382650311673568542237852546715913135688434614731717844868261",
        "309133826845331278722882330592890120369379620942948199356542318795450228858357445635314757",
        "976522637021306403150551933319006137720124048624544172072735055780411834104862667155922841",
        "635752334942676003169313626814655695963315290125751655287486460091602385142405742365191277",
        "625161793954624746211679299331621567931369768944205635791355694727774487677706013842058779",
        "204005728266090048777253207241416669051476369216501266754813821619984472224780876488344279" ]
  for p in P
    T.assert fermat2_test(nbs(p)), "Prime #{p}"
  cb()
