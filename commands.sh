curl -k \
  --cert ./wallet_certs/wallet.crt \
  --key  ./wallet_certs/wallet.key \
  -H "Content-Type: application/json" \
    -d '{"student_id":"stud008","exam_name":"Programmazione Avanzata","exam_date":"2025-07-05"}' \
  https://localhost:8003/request

CID=0817dc7f-7a27-4a7a-af61-94c71225c652
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

CID=b659aff4-7309-46c4-88a2-48c0afbff0b6
curl -k \
  --cert admin.crt \
  --key  admin.key \
  -H "Content-Type: application/json" \
  -d "{\"credential_id\":\"$CID\"}" \
  https://localhost:8001/revoke