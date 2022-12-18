module gen

go 1.19

replace encryption => ../encryption/

require (
	encryption v0.0.0-00010101000000-000000000000
	generator v0.0.0-00010101000000-000000000000
	hashing v0.0.0-00010101000000-000000000000
)

replace hashing => ../hashing/

replace generator => ../generator
