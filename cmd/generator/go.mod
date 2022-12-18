module generator

go 1.19

replace encryption => ../encryption/

replace hashing => ../hashing/

require (
	encryption v0.0.0-00010101000000-000000000000
	hashing v0.0.0-00010101000000-000000000000
)
