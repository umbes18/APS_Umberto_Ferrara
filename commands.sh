curl -k \
  --cert ./wallet_certs/wallet.crt \
  --key  ./wallet_certs/wallet.key \
  -H "Content-Type: application/json" \
    -d '{"student_id":"stud007","exam_name":"Machine Learning","exam_date":"2025-07-01"}' \
  https://localhost:8003/request

CID=9f75b8cf-8551-4d5d-9170-29604a2d557b
curl -k --cert ./wallet_certs/wallet.crt \
     --key  ./wallet_certs/wallet.key \
     -H 'Content-Type: application/json' \
     -d '{"credential_id":"'"$CID"'","need":["exam_name","grade"]}' \
     https://localhost:8003/present \
     -o pres.json

curl -k --cert ./wallet_certs/wallet.crt \
     --key  ./wallet_certs/wallet.key \
     -H 'Content-Type: application/json' \
     --data-binary @pres.json \
     https://localhost:8004/verify | jq .

CID=9f75b8cf-8551-4d5d-9170-29604a2d557b
curl -k \
  --cert admin.crt \
  --key  admin.key \
  -H "Content-Type: application/json" \
  -d "{\"credential_id\":\"$CID\"}" \
  https://localhost:8001/revoke