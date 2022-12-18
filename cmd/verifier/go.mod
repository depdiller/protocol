module verifier

go 1.19

replace encryption => ../encryption/

require verification v0.0.0-00010101000000-000000000000

require encryption v0.0.0-00010101000000-000000000000 // indirect

replace verification => ../verification/
