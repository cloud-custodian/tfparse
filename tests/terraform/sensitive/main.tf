# GH-253 - tfparse crashing on sensitive block.
locals {
  sensitive-thing     = sensitive("FAKE-SENSITIVE-VALUE")
  non-sensitive-thing = "NON-SENSITIVE-THING"
}
