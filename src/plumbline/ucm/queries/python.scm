;; Python Tree-Sitter UCM query

;; Function definitions
(function_definition
  name: (identifier) @symbol.function.name
  parameters: (parameters) @symbol.function.params) @symbol.function.def

;; Class definitions
(class_definition
  name: (identifier) @symbol.class.name) @symbol.class.def

;; Imports
(import_statement
  name: (dotted_name) @import.module) @import.def

(import_from_statement
  module_name: (dotted_name)? @import.from_module
  name: (dotted_name) @import.name) @import.def

;; Comments
(comment) @comment.text

;; String literals
(string) @string.lit

;; Call sites
(call
  function: [
    (identifier) @call.callee
    (attribute attribute: (identifier) @call.callee)
  ]
  arguments: (argument_list) @call.args) @call.site
