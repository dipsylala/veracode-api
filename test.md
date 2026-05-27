# MCPVerademo — STATIC findings

**Total:** 139 | **Page:** 1 | **Size:** 3 | **Build:** 64461994

| ID | Sev | CWE | Status | Policy | File | Line | Attack Vector |
|:--|:--|:--|:--|:--|:--|--:|:--|
| 7 | 4 | 89 | CLOSED | ✓ | UserController.java | 249 | java.sql.Statement.executeQuery |
| 8 | 4 | 89 | OPEN | ✓ | UserController.java | 310 | java.sql.Statement.executeQuery |
| 9 | 4 | 89 | OPEN | ✓ | UserController.java | 374 | java.sql.Statement.execute |

## Detailed Findings

### Finding 7 · severity 4 · CWE-89
**Location:** com/veracode/verademo/controller/UserController.java:249 · **Module:** verademo.war  
**Attack vector:** java.sql.Statement.executeQuery  

#### Mitigations for finding 7

| Action | User | Date | Notes |
|:--|:--|:--|:--|
| APPROVED | Verainternal MCP | 2025-12-11T22:58:23.438Z | Accepting the risk!!! |
| APPDESIGN | Verainternal MCP | 2025-12-11T16:55:10.005Z | Another proposal |
| COMMENT | Verainternal MCP | 2025-12-11T00:35:06.142Z | This is a comment |
| APPDESIGN | Marcus Watson | 2025-10-13T17:18:46.388Z | Technique : M1 : Establish and maintain control over all of your inputs Specifics : test Remaining Risk : test Verification : test Specifics: test Technique: M1 : Establish and maintain control over all of your inputs Remaining risk: test Verification: test |

### Finding 8 · severity 4 · CWE-89
**Location:** com/veracode/verademo/controller/UserController.java:310 · **Module:** verademo.war  
**Attack vector:** java.sql.Statement.executeQuery  

#### Mitigations for finding 8

| Action | User | Date | Notes |
|:--|:--|:--|:--|
| COMMENT | Verainternal MCP | 2025-12-11T00:11:57.002Z | New comment? |
| COMMENT | Verainternal MCP | 2025-12-10T23:47:32.576Z | Another comment! |
| COMMENT | Verainternal MCP | 2025-12-10T23:47:24.092Z | more comments |
| COMMENT | Verainternal MCP | 2025-12-10T23:46:07.413Z | This is a test. There are many like it but this one is mine |

### Finding 9 · severity 4 · CWE-89
**Location:** com/veracode/verademo/controller/UserController.java:374 · **Module:** verademo.war  
**Attack vector:** java.sql.Statement.execute  

#### Mitigations for finding 9

| Action | User | Date | Notes |
|:--|:--|:--|:--|
| FP | Verainternal MCP | 2025-12-11T22:59:44.781Z | This is a false positive! |
| COMMENT | Verainternal MCP | 2025-12-11T00:14:58.251Z | This is a comment There are many like it but this one is mine |

