;; Go Tree-Sitter UCM query

(function_declaration
  name: (identifier) @symbol.function.name
  parameters: (parameter_list) @symbol.function.params) @symbol.function.def

(method_declaration
  name: (field_identifier) @symbol.function.name
  parameters: (parameter_list) @symbol.function.params) @symbol.function.def

(type_spec
  name: (type_identifier) @symbol.class.name) @symbol.class.def

(import_spec
  path: (interpreted_string_literal) @import.module) @import.def

(comment) @comment.text
(interpreted_string_literal) @string.lit

(call_expression
  function: [
    (identifier) @call.callee
    (selector_expression field: (field_identifier) @call.callee)
  ]
  arguments: (argument_list) @call.args) @call.site
