module crack

go 1.19

replace verification => ../verification/

replace encryption => ../encryption/

require (
	hashing v0.0.0-00010101000000-000000000000
	verification v0.0.0-00010101000000-000000000000
)

require (
	encryption v0.0.0-00010101000000-000000000000
	generator v0.0.0-00010101000000-000000000000
)

replace hashing => ../hashing/

replace generator => ../generator
