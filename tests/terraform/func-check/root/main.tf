
# The absolute-path case cannot be written as a literal: a path that exists on
# every machine (say "/etc") makes the assertion depend on that directory's
# contents, and abspath() resolves against the process working directory rather
# than the module. So the test injects the module's own path as a tfvar.
variable "abs_files_dir" {
  type        = string
  description = "Absolute path to this module's files/ directory, supplied by the test."
}

locals {

  check_mod_path = path.module

  check_toset_int = toset([1, 2, 3])
  check_toset_str = toset(["a", "b", "c"])

  check_tomap  = tomap({ "a" = 1, "b" = 2 })
  check_tolist = tolist(["a", "b", "c"])

  check_fileexists = fileexists("${path.module}/readme.md")
  check_file       = file("${path.module}/readme.md")

  check_fileset_abs_path      = fileset(var.abs_files_dir, "*.py")
  check_fileset_rel_path      = fileset("files", "*.py")
  check_fileset_mod_path      = fileset("${path.module}/files", "*")
  check_fileset_wild_rel_path = fileset("${path.module}", "files/*.py")

  check_trimprefix = trimprefix("abc/def", "abc")

  modules_list = toset([for lambda_main in fileset("${path.module}/modules/*/", "main.tf") : trimsuffix(trimprefix(lambda_main, "../"), "/main.tf")])
  lambdas_list = toset([for lambda_main in fileset("${path.module}/../lambdas/*/", "main.go") : trimsuffix(trimprefix(lambda_main, "../"), "/main.go")])
}
