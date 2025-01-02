# Nitro Enclave demo (`ned`)

<img src=".github/logo.png" width="400">

This is a demo for [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) capabilities that attempts to fill in the gaps and inconsistencies in the official documentation (as of January 2025).

Probably unneccesary **disclaimer**: making attestation documents available to the host (like this demo does) defeats the entire purpose of using Nitro Enclaves and should not be used for anything else than testing.

## Setup

Running `bin/setup true` will deploy a CloudFormation that deploys the required infrastructure. Leaving out the "true" parameter will deploy everything except the EC2 instance. Re-running `bin/setup` will update the stack, potentially creating or destroying the associated instance.

The stack uses spot to allocate an instance. If this fails in your region, pick another instance class, region or wait until capacity is available.

## Usage

After the setup is complete and provisioning is done, there are two options:

1. Call `bin/connect` to connect to the instance
2. Call `bin/build` to build the enclave, run it and run the host part to show results like the following:

```
2025/01/02 12:56:03 INFO fetched configuration from imds KeyID=0063c4a6-...
2025/01/02 12:56:03 INFO generated RSA keypair - this is dynamic and may or may not be ephemeral / rotated etc
2025/01/02 12:56:03 INFO converted public key to ASN.1 DER
([]uint8) (len=294 cap=294) {
 00000000  30 82 01 22 30 0d 06 09  2a 86 48 86 f7 0d 01 01  |0.."0...*.H.....|
...
 00000120  11 02 03 01 00 01                                 |......|
}
2025/01/02 12:56:03 INFO requested and received attestation document from enclave in the form of an untagged COSE message
([]uint8) (len=4783 cap=4785) {
 00000000  84 44 a1 01 38 22 a0 59  12 43 a9 69 6d 6f 64 75  |.D..8".Y.C.imodu|
...
 000012a0  6f cc c0 0b da 54 dc 32  77 39 34 27 2f d8 93     |o....T.2w94'/..|
}
2025/01/02 12:56:03 INFO upstream recipients (like KMS) decode and verify this document and inspect the fields to verify the attestation
(*network.Document)(0x40000926e0)({
 CABundle: ([][]uint8) <nil>,
 Certificate: ([]uint8) (len=645 cap=645) {
  00000000  30 82 02 81 30 82 02 07  a0 03 02 01 02 02 10 01  |0...0...........|
...
 Timestamp: (uint64) 1735822563593,
 UserData: ([]uint8) <nil>
})
2025/01/02 12:56:03 INFO encrypted message plaintext="hello world - goodbye world!"
([]uint8) (len=180 cap=180) {
 00000000  01 02 02 00 78 6a 6c 74  0d 5a 5f b7 e9 e4 88 ef  |....xjlt.Z_.....|
...
 000000b0  a5 b0 7f 19                                       |....|
}
2025/01/02 12:56:03 INFO decryption without attestation document failed as expected error="operation error KMS: Decrypt, https response error StatusCode: 400, RequestID: 9a473643-..., api error AccessDeniedException: User: arn:aws:sts::...:assumed-role/NEDHostRole/i-01926a3f257718e16 is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:eu-central-1:...:key/0063c4a6-... because no resource-based policy allows the kms:Decrypt action"
2025/01/02 12:56:03 INFO decrypted message, leading to an empty plaintext blob and a present ciphertext for recipient plaintext_len=0 ciphertext_for_recipient_len=477
2025/01/02 12:56:03 INFO ciphertext for recipient is a BER encoded RCF5652 CMS message - it can be parsed using 'xxd -r -p | openssl cms -inform DER -cmsout -print' BER=308006092a864886f70d010703a08030800201023182016b308201670201028020a5281703e7f074991fdabdc30b83edc8c3a131eecafb5ed21c15f9c7fc1a23f9303c06092a864886f70d010107302fa00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500048201009f974f1e780788b9d30ca9cad9c1d8ec580c1eb13447bd26cd35654102d48a36dbea92e22a611920b391a0706b0e2dfe7250d4a304301398bff3531b5a49bb0164e8aec196a7aac3ac0ae7d9bed042b632f33bc4e1718abdcf5df7a73da6003fb6e14ae35169a444138977b3ec9b138d9bf22d834c0f37d5e63aa3fafbb88f11ffde750859dbf7cd973fb91df384fa81ea14f188f76f52b235b960a8bb749e0d3bfec0d43c6c0334937509e8e5183d4523bbb30f0c098578a3204fffc5d3c9830ab9409dc7aa4f675596290401c652953522326c7a07004e83c534be4154f7095342a445901289ecbeef8ff1b695fb0b800a2a03e5331eac38d0c4a5b284f604308006092a864886f70d010701301d060960864801650304012a04105aab36bcfa098ce7cde7ea47f3f51957a0800420469d82fa4b12cf68a18be23bd1ef737f1e2d15f0c8f171477afb6c4e4000e41b00000000000000000000
2025/01/02 12:56:03 INFO converted BER to DER to enable parsing through the golang standard library
2025/01/02 12:56:03 INFO decrypted encrypted key part of the CMS message using OAEP and our private key key="\x83N5\xd7\x17\xaf7\xb0u5{\xebB\xda- g\x9c\x19\x85r\t\xb0\xd310\xac\xe8̅d{"
2025/01/02 12:56:03 INFO decrypting aes-cbc block block=0 blocks=2
2025/01/02 12:56:03 INFO decrypting aes-cbc block block=1 blocks=2
2025/01/02 12:56:03 INFO removing pkcs#7 padding pad=4
2025/01/02 12:56:03 INFO successfully decrypted message using AES-CBC plaintext="hello world - goodbye world!"
```

Following up on the log message about decoding the CMS message will result in the following:

```
CMS_ContentInfo:
  contentType: pkcs7-envelopedData (1.2.840.113549.1.7.3)
  d.envelopedData:
    version: 2
    originatorInfo: <ABSENT>
    recipientInfos:
      d.ktri:
        version: 2
        d.subjectKeyIdentifier:
          0000 - a5 28 17 03 e7 f0 74 99-1f da bd c3 0b 83 ed   .(....t........
          000f - c8 c3 a1 31 ee ca fb 5e-d2 1c 15 f9 c7 fc 1a   ...1...^.......
          001e - 23 f9                                          #.
        keyEncryptionAlgorithm:
          algorithm: rsaesOaep (1.2.840.113549.1.1.7)
          parameter: SEQUENCE:
    0:d=0  hl=2 l=  47 cons: SEQUENCE
    2:d=1  hl=2 l=  15 cons:  cont [ 0 ]
    4:d=2  hl=2 l=  13 cons:   SEQUENCE
    6:d=3  hl=2 l=   9 prim:    OBJECT            :sha256
   17:d=3  hl=2 l=   0 prim:    NULL
   19:d=1  hl=2 l=  28 cons:  cont [ 1 ]
   21:d=2  hl=2 l=  26 cons:   SEQUENCE
   23:d=3  hl=2 l=   9 prim:    OBJECT            :mgf1
   34:d=3  hl=2 l=  13 cons:    SEQUENCE
   36:d=4  hl=2 l=   9 prim:     OBJECT            :sha256
   47:d=4  hl=2 l=   0 prim:     NULL
        encryptedKey:
          0000 - 9f 97 4f 1e 78 07 88 b9-d3 0c a9 ca d9 c1 d8   ..O.x..........
          000f - ec 58 0c 1e b1 34 47 bd-26 cd 35 65 41 02 d4   .X...4G.&.5eA..
          001e - 8a 36 db ea 92 e2 2a 61-19 20 b3 91 a0 70 6b   .6....*a. ...pk
          002d - 0e 2d fe 72 50 d4 a3 04-30 13 98 bf f3 53 1b   .-.rP...0....S.
          003c - 5a 49 bb 01 64 e8 ae c1-96 a7 aa c3 ac 0a e7   ZI..d..........
          004b - d9 be d0 42 b6 32 f3 3b-c4 e1 71 8a bd cf 5d   ...B.2.;..q...]
          005a - f7 a7 3d a6 00 3f b6 e1-4a e3 51 69 a4 44 13   ..=..?..J.Qi.D.
          0069 - 89 77 b3 ec 9b 13 8d 9b-f2 2d 83 4c 0f 37 d5   .w.......-.L.7.
          0078 - e6 3a a3 fa fb b8 8f 11-ff de 75 08 59 db f7   .:........u.Y..
          0087 - cd 97 3f b9 1d f3 84 fa-81 ea 14 f1 88 f7 6f   ..?...........o
          0096 - 52 b2 35 b9 60 a8 bb 74-9e 0d 3b fe c0 d4 3c   R.5.`..t..;...<
          00a5 - 6c 03 34 93 75 09 e8 e5-18 3d 45 23 bb b3 0f   l.4.u....=E#...
          00b4 - 0c 09 85 78 a3 20 4f ff-c5 d3 c9 83 0a b9 40   ...x. O.......@
          00c3 - 9d c7 aa 4f 67 55 96 29-04 01 c6 52 95 35 22   ...OgU.)...R.5"
          00d2 - 32 6c 7a 07 00 4e 83 c5-34 be 41 54 f7 09 53   2lz..N..4.AT..S
          00e1 - 42 a4 45 90 12 89 ec be-ef 8f f1 b6 95 fb 0b   B.E............
          00f0 - 80 0a 2a 03 e5 33 1e ac-38 d0 c4 a5 b2 84 f6   ..*..3..8......
          00ff - 04                                             .
    encryptedContentInfo:
      contentType: pkcs7-data (1.2.840.113549.1.7.1)
      contentEncryptionAlgorithm:
        algorithm: aes-256-cbc (2.16.840.1.101.3.4.1.42)
        parameter: OCTET STRING:
          0000 - 5a ab 36 bc fa 09 8c e7-cd e7 ea 47 f3 f5 19   Z.6........G...
          000f - 57                                             W
      encryptedContent:
        0000 - 46 9d 82 fa 4b 12 cf 68-a1 8b e2 3b d1 ef 73   F...K..h...;..s
        000f - 7f 1e 2d 15 f0 c8 f1 71-47 7a fb 6c 4e 40 00   ..-....qGz.lN@.
        001e - e4 1b                                          ..
    unprotectedAttrs:
      <ABSENT>
```

The result of a successful decryption operation will yield an additional "additionalEventData" field in the CloudTrail log event that contains data about the PCRs of the enclave:

```
    "additionalEventData": {
        "recipient": {
            "attestationDocumentEnclavePCR4": "15u0...b9Xa",
            "attestationDocumentEnclavePCR8": "AAAA...AAAA",
            "attestationDocumentModuleId": "i-04ac...faf3-enc01941...98cd",
            "attestationDocumentEnclaveImageDigest": "T37s...7ToS",
            "attestationDocumentEnclavePCR1": "O0p+...l00D",
            "attestationDocumentEnclavePCR3": "lX2u...Tq6q",
            "attestationDocumentEnclavePCR2": "Ovyr...eSxR"
        }
    },
```