curl -k \
  --cert ./wallet_certs/wallet.crt \
  --key  ./wallet_certs/wallet.key \
  -H "Content-Type: application/json" \
    -d '{"student_id":"stud007","exam_name":"Sistemi Distribuiti","exam_date":"2025-07-03"}' \
  https://localhost:8003/request

CID=f68bdc80-b723-44f2-9458-19b530d358d9
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

CID=f68bdc80-b723-44f2-9458-19b530d358d9
curl -k \
  --cert admin.crt \
  --key  admin.key \
  -H "Content-Type: application/json" \
  -d "{\"credential_id\":\"$CID\"}" \
  https://localhost:8001/revoke