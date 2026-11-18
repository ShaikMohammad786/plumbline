;; TypeScript Tree-Sitter UCM query

(function_declaration
  name: (identifier) @symbol.function.name
  parameters: (formal_parameters) @symbol.function.params) @symbol.function.def

(class_declaration
  name: (type_identifier) @symbol.class.name) @symbol.class.def

(import_statement
  source: (string) @import.module) @import.def

(comment) @comment.text
(string) @string.lit

(call_expression
  function: [
    (identifier) @call.callee
    (member_expression property: (property_identifier) @call.callee)
  ]
  arguments: (arguments) @call.args) @call.site
