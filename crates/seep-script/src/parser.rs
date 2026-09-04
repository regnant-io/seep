use std::collections::HashMap;
use crate::lexer::Token;

#[derive(Debug, Clone)]
pub struct ScriptMeta {
    pub name: Option<String>,
    pub version: Option<String>,
    pub author: Option<String>,
    pub requires: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Statement {
    Think(String),
    Shell(String),
    Mcp { tool: String, args: HashMap<String, String> },
    Ask(String),
    Set { var: String, value: String },
    IfThink { condition: String, body: Vec<Statement> },
    OnError(Vec<Statement>),
    Preview(Vec<Statement>),
    Parallel(Vec<Statement>),
    Notify(String),
    Abort(String),
    Checkpoint(String),
    Comment(String),
}

#[derive(Debug, Clone)]
pub struct Script {
    pub meta: ScriptMeta,
    pub statements: Vec<Statement>,
}

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> &Token {
        let t = &self.tokens[self.pos];
        self.pos += 1;
        t
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Token::Newline | Token::Comment(_)) {
            self.advance();
        }
    }

    fn expect_string(&mut self) -> Option<String> {
        self.skip_newlines();
        if let Token::StringLit(s) = self.peek().clone() {
            self.advance();
            Some(s)
        } else {
            None
        }
    }

    fn parse_kv_args(&mut self) -> HashMap<String, String> {
        let mut args = HashMap::new();
        // Read key=value pairs until newline or EOF
        loop {
            self.skip_newlines();
            match self.peek().clone() {
                Token::Ident(key) => {
                    self.advance();
                    if matches!(self.peek(), Token::Assign) {
                        self.advance();
                        match self.peek().clone() {
                            Token::StringLit(val) => {
                                self.advance();
                                args.insert(key, val);
                            }
                            Token::Ident(val) => {
                                self.advance();
                                args.insert(key, val);
                            }
                            _ => { args.insert(key, String::new()); }
                        }
                    }
                }
                Token::Newline | Token::Eof => break,
                _ => { self.advance(); }
            }
        }
        args
    }

    fn parse_block(&mut self) -> Vec<Statement> {
        let mut stmts = vec![];
        self.skip_newlines();
        // Indented block - read until we hit a non-indented keyword or EOF
        // Simple heuristic: read statements until we see an unindented keyword
        loop {
            self.skip_newlines();
            match self.peek() {
                Token::Eof => break,
                Token::Think | Token::Shell | Token::Mcp | Token::Ask
                | Token::Set | Token::If | Token::OnError | Token::Preview
                | Token::Parallel | Token::Notify | Token::Abort | Token::Checkpoint => {
                    if let Some(stmt) = self.parse_statement() {
                        stmts.push(stmt);
                    }
                }
                _ => break,
            }
        }
        stmts
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        self.skip_newlines();
        match self.peek().clone() {
            Token::Eof => None,

            Token::Comment(c) => {
                self.advance();
                Some(Statement::Comment(c))
            }

            Token::Think => {
                self.advance();
                // think "..." or think("...")
                let directive = self.expect_string()?;
                Some(Statement::Think(directive))
            }

            Token::Shell => {
                self.advance();
                let cmd = self.expect_string()?;
                Some(Statement::Shell(cmd))
            }

            Token::Mcp => {
                self.advance();
                // mcp tool_name key=val key=val
                let tool = if let Token::Ident(t) = self.peek().clone() {
                    self.advance();
                    t
                } else { return None; };
                let args = self.parse_kv_args();
                Some(Statement::Mcp { tool, args })
            }

            Token::Ask => {
                self.advance();
                let prompt = self.expect_string()?;
                Some(Statement::Ask(prompt))
            }

            Token::Set => {
                self.advance();
                let var = if let Token::Ident(v) = self.peek().clone() {
                    self.advance(); v
                } else { return None; };
                if matches!(self.peek(), Token::Assign) { self.advance(); }
                let value = match self.peek().clone() {
                    Token::StringLit(s) => { self.advance(); s }
                    Token::Ident(s) => { self.advance(); s }
                    _ => String::new(),
                };
                Some(Statement::Set { var, value })
            }

            Token::If => {
                self.advance();
                let condition = self.expect_string()?;
                if matches!(self.peek(), Token::Colon) { self.advance(); }
                let body = self.parse_block();
                Some(Statement::IfThink { condition, body })
            }

            Token::OnError => {
                self.advance();
                if matches!(self.peek(), Token::Colon) { self.advance(); }
                let body = self.parse_block();
                Some(Statement::OnError(body))
            }

            Token::Preview => {
                self.advance();
                if matches!(self.peek(), Token::Colon) { self.advance(); }
                let body = self.parse_block();
                Some(Statement::Preview(body))
            }

            Token::Parallel => {
                self.advance();
                if matches!(self.peek(), Token::Colon) { self.advance(); }
                let body = self.parse_block();
                Some(Statement::Parallel(body))
            }

            Token::Notify => {
                self.advance();
                let msg = self.expect_string()?;
                Some(Statement::Notify(msg))
            }

            Token::Abort => {
                self.advance();
                let msg = self.expect_string()?;
                Some(Statement::Abort(msg))
            }

            Token::Checkpoint => {
                self.advance();
                let label = self.expect_string()?;
                Some(Statement::Checkpoint(label))
            }

            Token::At(_meta) => {
                // Already handled in parse_meta
                self.advance();
                None
            }

            _ => {
                self.advance();
                None
            }
        }
    }

    pub fn parse(mut self) -> anyhow::Result<Script> {
        let mut meta = ScriptMeta {
            name: None,
            version: None,
            author: None,
            requires: vec![],
        };
        let mut statements = vec![];

        // First pass: collect @directives and statements
        while !matches!(self.peek(), Token::Eof) {
            self.skip_newlines();
            match self.peek().clone() {
                Token::At(directive) => {
                    self.advance();
                    if let Some((key, val)) = directive.split_once(':') {
                        match key.trim() {
                            "name"     => meta.name = Some(val.trim().to_string()),
                            "version"  => meta.version = Some(val.trim().to_string()),
                            "author"   => meta.author = Some(val.trim().to_string()),
                            "requires" => {
                                meta.requires = val.split(',')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect();
                            }
                            _ => {}
                        }
                    }
                }
                Token::Eof => break,
                _ => {
                    if let Some(stmt) = self.parse_statement() {
                        statements.push(stmt);
                    }
                }
            }
        }

        Ok(Script { meta, statements })
    }
}
