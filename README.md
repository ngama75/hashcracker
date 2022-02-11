# Hashcracker

A robot for designed to communicate with the http://hachcrack.algonics.net backend:

| method | url | input | output
| ---- | ----- | ------ | ----- |
| POST | /api/register | `{}` | `wid` (worker_id string) |
| POST | /api/get-challenge | `{cid?, wid}` | `{cid, salt: <base64>, target: <base64>}` |
| POST | /api/submit-solution | `{wid, cid, solution: <base64>` | `{success: true}`

just compile and run hashcracker :-)

## Build instructions (TBC)

### build dependencies: mbedtls, json11, cmake

### runtime dependencies: curl, mbedtls, json11

### build instructions: general cmake
