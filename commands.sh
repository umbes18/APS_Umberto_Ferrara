curl -k \
  --cert ./wallet_certs/wallet.crt \
  --key  ./wallet_certs/wallet.key \
  -H "Content-Type: application/json" \
    -d '{"student_id":"stud002","exam_name":"Criptografia","exam_date":"2025-06-22"}' \
  https://localhost:8003/request

CID=b1c8c5ef-5dc3-42da-a618-0c70297954f8
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

CID=b1c8c5ef-5dc3-42da-a618-0c70297954f8
curl -k \
  --cert admin.crt \
  --key  admin.key \
  -H "Content-Type: application/json" \
  -d "{\"credential_id\":\"$CID\"}" \
  https://localhost:8001/revoke