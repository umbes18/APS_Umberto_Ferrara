curl -k -sS \
  --cert ./wallet_certs/wallet.crt \
  --key  ./wallet_certs/wallet.key \
  -H "Content-Type: application/json" \
  -d '{"student_id":"stud009"}' \
  https://localhost:8003/request | jq .

curl -k \
     --cert   ./wallet_certs/wallet.crt \
     --key    ./wallet_certs/wallet.key \
     -sS https://localhost:8004/challenge \
     -H 'Content-Type: application/json' \
     -d '{"need":["exam_name","exam_date","grade"]}' > challenge.json

CID='6b888c30-d52d-475f-8a47-cc5615a0841d'
NEED=$(jq -c '.need'      challenge.json)
CH=$(jq  -r '.challenge'  challenge.json)
AUD=$(jq -r '.audience'   challenge.json)
RID=$(jq -r '.request_id' challenge.json)
EXP=$(jq -r '.expires_at' challenge.json)

# 3) costruisci il body in modo sicuro
jq -n \
  --arg cid "$CID" \
  --arg ch  "$CH" \
  --arg aud "$AUD" \
  --arg rid "$RID" \
  --arg exp "$EXP" \
  --argjson need "$NEED" \
  '{credential_id:$cid, need:$need, challenge:$ch, audience:$aud, request_id:$rid, expires_at:$exp}' \
  > present_body.json

jq . present_body.json   # deve stampare JSON valido

# 4) chiedi la presentation al wallet (mTLS) e salva in pres.json
curl -k -sS \
  --cert ./wallet_certs/wallet.crt \
  --key  ./wallet_certs/wallet.key \
  -H 'Content-Type: application/json' \
  --data-binary @present_body.json \
  https://localhost:8003/present > pres.json

jq . pres.json           # deve stampare JSON valido

curl -k \
     --cert   ./wallet_certs/wallet.crt \
     --key    ./wallet_certs/wallet.key \
     -sS https://localhost:8004/verify \
     -H 'Content-Type: application/json' \
     --data-binary @pres.json | jq .


# Revoke credential
CID=6b888c30-d52d-475f-8a47-cc5615a0841d
curl -k \
  --cert admin.crt \
  --key  admin.key \
  -H "Content-Type: application/json" \
  -d "{\"credential_id\":\"$CID\"}" \
  https://localhost:8001/revoke