;; Java Tree-Sitter UCM query

(method_declaration
  name: (identifier) @symbol.function.name
  parameters: (formal_parameters) @symbol.function.params) @symbol.function.def

(class_declaration
  name: (identifier) @symbol.class.name) @symbol.class.def

(import_declaration
  name: (scoped_identifier) @import.module) @import.def

(line_comment) @comment.text
(block_comment) @comment.text
(string_literal) @string.lit

(method_invocation
  name: (identifier) @call.callee
  arguments: (argument_list) @call.args) @call.site
