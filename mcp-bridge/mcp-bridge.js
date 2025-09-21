#!/usr/bin/env node

/**
 * MCP Bridge Server for Developer Utilities
 * This server acts as a bridge between MCP protocol and the HTTP-based dev-utilities server
 */

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require('@modelcontextprotocol/sdk/types.js');
const axios = require('axios');

// Configuration
const BASE_URL = process.env.DEV_UTILS_BASE_URL || 'http://localhost:8080/api/v1';
const SERVER_PORT = process.env.SERVER_PORT || '8080';

class DevUtilitiesMCPServer {
  constructor() {
    this.server = new Server(
      {
        name: 'dev-utilities-mcp',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    this.setupErrorHandling();
  }

  setupErrorHandling() {
    this.server.onerror = (error) => {
      console.error('[MCP Server Error]', error);
    };

    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          // Crypto tools
          {
            name: 'crypto_hash',
            description: 'Generate hash (MD5, SHA1, SHA256, SHA512) for given content',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Content to hash' },
                algorithm: { 
                  type: 'string', 
                  enum: ['md5', 'sha1', 'sha256', 'sha512'],
                  description: 'Hash algorithm to use'
                }
              },
              required: ['content', 'algorithm']
            }
          },
          {
            name: 'crypto_hmac',
            description: 'Generate HMAC for given content and secret key',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Content to sign' },
                secret: { type: 'string', description: 'Secret key for HMAC' },
                algorithm: { 
                  type: 'string', 
                  enum: ['sha256', 'sha512'],
                  description: 'HMAC algorithm to use'
                }
              },
              required: ['content', 'secret', 'algorithm']
            }
          },
          {
            name: 'crypto_password_hash',
            description: 'Hash password using Argon2id',
            inputSchema: {
              type: 'object',
              properties: {
                password: { type: 'string', description: 'Password to hash' }
              },
              required: ['password']
            }
          },
          {
            name: 'crypto_password_verify',
            description: 'Verify password against Argon2id hash',
            inputSchema: {
              type: 'object',
              properties: {
                password: { type: 'string', description: 'Password to verify' },
                hash: { type: 'string', description: 'Hash to verify against' }
              },
              required: ['password', 'hash']
            }
          },
          {
            name: 'crypto_cert_decode',
            description: 'Decode PEM-encoded X.509 certificate',
            inputSchema: {
              type: 'object',
              properties: {
                certificate: { type: 'string', description: 'PEM-encoded certificate' }
              },
              required: ['certificate']
            }
          },
          
          // Text tools
          {
            name: 'text_case_convert',
            description: 'Convert text case (uppercase, lowercase, title, camel, pascal, snake, kebab)',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Text to convert' },
                case_type: { 
                  type: 'string', 
                  enum: ['uppercase', 'lowercase', 'title', 'camel', 'pascal', 'snake', 'kebab'],
                  description: 'Target case type'
                }
              },
              required: ['content', 'case_type']
            }
          },
          {
            name: 'text_analyze',
            description: 'Analyze text (character count, word count, line count, etc.)',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Text to analyze' }
              },
              required: ['content']
            }
          },
          {
            name: 'text_regex_test',
            description: 'Test regex pattern against text',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Text to test against' },
                pattern: { type: 'string', description: 'Regex pattern' },
                flags: { type: 'string', description: 'Regex flags (optional)' }
              },
              required: ['content', 'pattern']
            }
          },
          {
            name: 'text_sort',
            description: 'Sort text lines alphabetically or numerically',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Text with lines to sort' },
                sort_type: { 
                  type: 'string', 
                  enum: ['alphabetical', 'numerical'],
                  description: 'Sort type'
                },
                reverse: { type: 'boolean', description: 'Reverse sort order' }
              },
              required: ['content', 'sort_type']
            }
          },

          // Transform tools
          {
            name: 'transform_base64_encode',
            description: 'Encode content to Base64',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Content to encode' },
                url_safe: { type: 'boolean', description: 'Use URL-safe Base64' }
              },
              required: ['content']
            }
          },
          {
            name: 'transform_base64_decode',
            description: 'Decode Base64 content',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Base64 content to decode' },
                url_safe: { type: 'boolean', description: 'Use URL-safe Base64' }
              },
              required: ['content']
            }
          },
          {
            name: 'transform_url_encode',
            description: 'URL encode content',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Content to URL encode' }
              },
              required: ['content']
            }
          },
          {
            name: 'transform_url_decode',
            description: 'URL decode content',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Content to URL decode' }
              },
              required: ['content']
            }
          },
          {
            name: 'transform_jwt_decode',
            description: 'Decode JWT token (header and payload only, no verification)',
            inputSchema: {
              type: 'object',
              properties: {
                token: { type: 'string', description: 'JWT token to decode' }
              },
              required: ['token']
            }
          },
          {
            name: 'transform_compress',
            description: 'Compress content using gzip or zlib',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Content to compress' },
                algorithm: { 
                  type: 'string', 
                  enum: ['gzip', 'zlib'],
                  description: 'Compression algorithm'
                }
              },
              required: ['content', 'algorithm']
            }
          },
          {
            name: 'transform_decompress',
            description: 'Decompress content using gzip or zlib',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Base64-encoded compressed content' },
                algorithm: { 
                  type: 'string', 
                  enum: ['gzip', 'zlib'],
                  description: 'Compression algorithm'
                }
              },
              required: ['content', 'algorithm']
            }
          },

          // ID generation tools
          {
            name: 'id_uuid_generate',
            description: 'Generate UUID (v1 or v4)',
            inputSchema: {
              type: 'object',
              properties: {
                version: { 
                  type: 'string', 
                  enum: ['v1', 'v4'],
                  description: 'UUID version'
                },
                count: { 
                  type: 'number', 
                  minimum: 1, 
                  maximum: 100,
                  description: 'Number of UUIDs to generate'
                }
              },
              required: ['version']
            }
          },
          {
            name: 'id_nanoid_generate',
            description: 'Generate Nano ID',
            inputSchema: {
              type: 'object',
              properties: {
                size: { 
                  type: 'number', 
                  minimum: 1, 
                  maximum: 100,
                  description: 'Length of Nano ID'
                },
                count: { 
                  type: 'number', 
                  minimum: 1, 
                  maximum: 100,
                  description: 'Number of Nano IDs to generate'
                }
              }
            }
          },

          // Time tools
          {
            name: 'time_convert',
            description: 'Convert time between formats (unix, iso8601, human)',
            inputSchema: {
              type: 'object',
              properties: {
                time: { type: 'string', description: 'Time value to convert' },
                from_format: { 
                  type: 'string', 
                  enum: ['unix', 'iso8601', 'human'],
                  description: 'Source format'
                },
                to_format: { 
                  type: 'string', 
                  enum: ['unix', 'iso8601', 'human'],
                  description: 'Target format'
                }
              },
              required: ['time', 'from_format', 'to_format']
            }
          },
          {
            name: 'time_now',
            description: 'Get current time in various formats',
            inputSchema: {
              type: 'object',
              properties: {
                format: { 
                  type: 'string', 
                  enum: ['unix', 'iso8601', 'human', 'all'],
                  description: 'Time format to return'
                }
              }
            }
          },

          // Network tools
          {
            name: 'network_url_parse',
            description: 'Parse URL into components',
            inputSchema: {
              type: 'object',
              properties: {
                url: { type: 'string', description: 'URL to parse' }
              },
              required: ['url']
            }
          },
          {
            name: 'network_url_build',
            description: 'Build URL from components',
            inputSchema: {
              type: 'object',
              properties: {
                scheme: { type: 'string', description: 'URL scheme (http, https)' },
                host: { type: 'string', description: 'Host name' },
                port: { type: 'number', description: 'Port number' },
                path: { type: 'string', description: 'URL path' },
                query: { type: 'string', description: 'Query string' },
                fragment: { type: 'string', description: 'URL fragment' }
              },
              required: ['scheme', 'host']
            }
          },
          {
            name: 'network_headers_inspect',
            description: 'Inspect HTTP headers of a URL (with SSRF protection)',
            inputSchema: {
              type: 'object',
              properties: {
                url: { type: 'string', description: 'URL to inspect headers for' }
              },
              required: ['url']
            }
          },
          {
            name: 'network_dns_lookup',
            description: 'Perform DNS lookup for various record types',
            inputSchema: {
              type: 'object',
              properties: {
                domain: { type: 'string', description: 'Domain to lookup' },
                record_type: { 
                  type: 'string', 
                  enum: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'],
                  description: 'DNS record type'
                }
              },
              required: ['domain', 'record_type']
            }
          },
          {
            name: 'network_ip_analyze',
            description: 'Analyze IP address (version, type, classification)',
            inputSchema: {
              type: 'object',
              properties: {
                ip: { type: 'string', description: 'IP address to analyze' }
              },
              required: ['ip']
            }
          },

          // Data formatting tools
          {
            name: 'data_json_format',
            description: 'Format or minify JSON',
            inputSchema: {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'JSON content to format' },
                action: { 
                  type: 'string', 
                  enum: ['format', 'minify'],
                  description: 'Format or minify'
                },
                indent: { 
                  type: 'number', 
                  minimum: 0, 
                  maximum: 8,
                  description: 'Indentation spaces (for format action)'
                }
              },
              required: ['content', 'action']
            }
          }
        ]
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      
      try {
        const result = await this.callTool(name, args);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2)
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`
            }
          ],
          isError: true
        };
      }
    });
  }

  async callTool(name, args) {
    console.error(`[DEBUG] Tool: ${name}`);
    console.error(`[DEBUG] Args:`, JSON.stringify(args, null, 2));
    
    // Map MCP tool calls to HTTP API endpoints
    const toolMapping = {
      // Crypto tools
      'crypto_hash': () => this.httpPost('/crypto/hash', { content: args.content, algorithm: args.algorithm }),
      'crypto_hmac': () => this.httpPost('/crypto/hmac', { content: args.content, key: args.secret, algorithm: args.algorithm }),
      'crypto_password_hash': () => this.httpPost('/crypto/password/hash', { password: args.password }),
      'crypto_password_verify': () => this.httpPost('/crypto/password/verify', { password: args.password, hash: args.hash }),
      'crypto_cert_decode': () => this.httpPost('/crypto/cert/decode', { certificate: args.certificate }),
      
      // Text tools
      'text_case_convert': () => {
        const caseTypeMap = {
          'uppercase': 'UPPERCASE',
          'lowercase': 'lowercase',
          'title': 'Title Case',
          'camel': 'camelCase',
          'pascal': 'PascalCase',
          'snake': 'snake_case',
          'kebab': 'kebab-case'
        };
        return this.httpPost('/text/case', { content: args.content, caseType: caseTypeMap[args.case_type] || args.case_type });
      },
      'text_analyze': () => this.httpPost('/text/info', { content: args.content }),
      'text_regex_test': () => this.httpPost('/text/regex', { content: args.content, pattern: args.pattern, flags: args.flags }),
      'text_sort': () => this.httpPost('/text/sort', { content: args.content, order: args.reverse ? 'desc' : 'asc', sortType: args.sort_type === 'alphabetical' ? 'alpha' : 'numeric' }),
      
      // Transform tools
      'transform_base64_encode': () => this.httpPost('/transform/base64', { action: 'encode', content: args.content, url_safe: args.url_safe }),
      'transform_base64_decode': () => this.httpPost('/transform/base64', { action: 'decode', content: args.content, url_safe: args.url_safe }),
      'transform_url_encode': () => this.httpPost('/transform/url', { action: 'encode', content: args.content }),
      'transform_url_decode': () => this.httpPost('/transform/url', { action: 'decode', content: args.content }),
      'transform_jwt_decode': () => this.httpPost('/transform/jwt/decode', { token: args.token }),
      'transform_compress': () => this.httpPost('/transform/compress', { action: 'compress', content: args.content, algorithm: args.algorithm }),
      'transform_decompress': () => this.httpPost('/transform/compress', { action: 'decompress', content: args.content, algorithm: args.algorithm }),
      
      // ID tools
      'id_uuid_generate': () => this.httpPost('/id/uuid', { version: args.version === 'v1' ? 1 : 4, count: args.count || 1 }),
      'id_nanoid_generate': () => this.httpPost('/id/nanoid', { size: args.size || 21, count: args.count || 1 }),
      
      // Time tools
      'time_convert': () => this.httpPost('/time/convert', { input: args.time, inputFormat: args.from_format, outputFormat: args.to_format }),
      'time_now': () => this.httpGet('/time/now', { format: args.format || 'all' }),
      
      // Network tools
      'network_url_parse': () => this.httpPost('/web/url', { action: 'parse', url: args.url }),
      'network_url_build': () => {
        const buildArgs = { action: 'build', scheme: args.scheme, host: args.host };
        if (args.path) buildArgs.path = args.path;
        if (args.fragment) buildArgs.fragment = args.fragment;
        if (args.query) {
          // Convert query string to object if needed
          if (typeof args.query === 'string') {
            const queryObj = {};
            args.query.split('&').forEach(pair => {
              const [key, value] = pair.split('=');
              queryObj[key] = value;
            });
            buildArgs.query = queryObj;
          } else {
            buildArgs.query = args.query;
          }
        }
        if (args.port) buildArgs.port = args.port;
        return this.httpPost('/web/url', buildArgs);
      },
      'network_headers_inspect': () => this.httpPost('/network/headers', { url: args.url }),
      'network_dns_lookup': () => this.httpPost('/network/dns', { domain: args.domain, recordType: args.record_type }),
      'network_ip_analyze': () => this.httpPost('/network/ip', { ip: args.ip }),
      
      // Data tools
      'data_json_format': () => this.httpPost('/data/json/format', { content: args.content, action: args.action, indent: args.indent })
    };

    const toolFunction = toolMapping[name];
    if (!toolFunction) {
      throw new Error(`Unknown tool: ${name}`);
    }

    try {
      const result = await toolFunction();
      console.error(`[DEBUG] Success:`, JSON.stringify(result, null, 2));
      return result;
    } catch (error) {
      console.error(`[DEBUG] Error:`, error.message);
      console.error(`[DEBUG] Error details:`, error.response?.data);
      throw error;
    }
  }

  async httpPost(endpoint, data) {
    console.error(`[DEBUG] POST ${BASE_URL}${endpoint}`);
    console.error(`[DEBUG] Payload:`, JSON.stringify(data, null, 2));
    
    try {
      const response = await axios.post(`${BASE_URL}${endpoint}`, data, {
        timeout: 10000,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      console.error(`[DEBUG] Response:`, JSON.stringify(response.data, null, 2));
      return response.data;
    } catch (error) {
      console.error(`[DEBUG] HTTP Error:`, error.response?.status, error.response?.data);
      throw error;
    }
  }

  async httpGet(endpoint, params = {}) {
    console.error(`[DEBUG] GET ${BASE_URL}${endpoint}`);
    console.error(`[DEBUG] Params:`, JSON.stringify(params, null, 2));
    
    try {
      const response = await axios.get(`${BASE_URL}${endpoint}`, {
        params,
        timeout: 10000
      });
      console.error(`[DEBUG] Response:`, JSON.stringify(response.data, null, 2));
      return response.data;
    } catch (error) {
      console.error(`[DEBUG] HTTP Error:`, error.response?.status, error.response?.data);
      throw error;
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Dev Utilities MCP Server running on stdio');
  }
}

// Start the server
if (require.main === module) {
  const server = new DevUtilitiesMCPServer();
  server.run().catch(console.error);
}

module.exports = { DevUtilitiesMCPServer };