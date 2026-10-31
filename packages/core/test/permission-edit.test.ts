import fs from "fs/promises"
import path from "path"
import { describe, expect } from "bun:test"
import { Effect, Layer } from "effect"
import { Agent } from "@opencode/core/agent"
import { Bus } from "@opencode/core/bus"
import { Database } from "@opencode/core/database/database"
import { AppNodeBuilder } from "@opencode/core/effect/app-node-builder"
import { Environment } from "@opencode/core/environment/index"
import { FileAccess } from "@opencode/core/file-access"
import { FileMutation } from "@opencode/core/file-mutation"
import { Formatter } from "@opencode/core/formatter"
import { Location } from "@opencode/core/location"
import { Permission } from "@opencode/core/permission"
import { PermissionSaved } from "@opencode/core/permission/saved"
import { Project } from "@opencode/core/project"
import { ProjectTable } from "@opencode/core/project/sql"
import { AbsolutePath } from "@opencode/core/schema"
import { Session } from "@opencode/core/session"
import { SessionTable } from "@opencode/core/session/sql"
import { SessionStore } from "@opencode/core/session/store"
import { Tool } from "@opencode/core/tool"
import { EditTool } from "@opencode/core/tool/plugin/edit"
import { WriteTool } from "@opencode/core/tool/plugin/write"
import { LayerNode } from "@opencode/util/effect/layer-node"
import { makeLocationNode } from "@opencode/util/effect/app-node"
import { location } from "./fixture/location"
import { withTempDir } from "./fixture/tmpdir"
import { testEffect } from "./lib/effect"
import { executeTool, registerToolPlugin, toolIdentity } from "./lib/tool"

// Real Agent rules + real Permission + real FileAccess + real edit/write tools; permissions are not mocked.
const agent = Agent.ID.make("permission-edit-test")
const sessionID = Session.ID.make("ses_permission_edit_test")

const writeToolNode = makeLocationNode({
  name: "test/permission-edit-write-plugin",
  layer: Layer.effectDiscard(registerToolPlugin(WriteTool.Plugin)),
  deps: [Tool.node, FileAccess.node, FileMutation.node, Environment.node, Formatter.node, Permission.node],
})

const editToolNode = makeLocationNode({
  name: "test/permission-edit-edit-plugin",
  layer: Layer.effectDiscard(registerToolPlugin(EditTool.Plugin)),
  deps: [
    Tool.node,
    FileAccess.node,
    FileMutation.node,
    Environment.node,
    Formatter.node,
    Location.node,
    Permission.node,
  ],
})

const call = (type: "write" | "edit", input: unknown, id = `call-${type}`) => ({
  sessionID,
  ...toolIdentity,
  agent,
  call: { type: "tool-call" as const, id, name: type, input },
})

const layer = (directory: string) =>
  AppNodeBuilder.build(
    LayerNode.group([
      Database.node,
      Bus.node,
      SessionStore.node,
      PermissionSaved.node,
      Agent.node,
      Permission.node,
      Tool.node,
      FileAccess.node,
      FileMutation.node,
      writeToolNode,
      editToolNode,
    ]),
    [
      Location.node.replace(
        Layer.succeed(Location.Service, Location.Service.of(location({ directory: AbsolutePath.make(directory) }))),
      ),
      Formatter.node.replace(Layer.mock(Formatter.Service, { file: () => Effect.succeed(false) })),
    ],
  )

const run = <A, E, R>(
  directory: string,
  rules: Permission.Ruleset,
  body: (registry: Tool.Interface) => Effect.Effect<A, E, R>,
) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    yield* db
      .insert(ProjectTable)
      .values({ id: Project.ID.global, worktree: AbsolutePath.make(directory), sandboxes: [] })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
    yield* db
      .insert(SessionTable)
      .values({
        id: sessionID,
        project_id: Project.ID.global,
        slug: "test",
        directory,
        title: "test",
        version: "test",
        agent,
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
    const agents = yield* Agent.Service
    yield* agents.transform((editor) =>
      editor.update(agent, (item) => {
        item.permissions = [...rules]
      }),
    )
    return yield* body(yield* Tool.Service)
  }).pipe(Effect.provide(layer(directory)))

const exists = (file: string) =>
  Effect.promise(() =>
    fs.access(file).then(
      () => true,
      () => false,
    ),
  )

const read = (file: string) => Effect.promise(() => fs.readFile(file, "utf8"))

const it = testEffect(Layer.empty)

describe("permission edit integration", () => {
  it.live("denies a write matched by a ./ deny rule and leaves no file", () =>
    withTempDir((tmp) =>
      run(
        tmp.path,
        [
          { action: "edit", resource: "*", effect: "allow" },
          { action: "edit", resource: "./secret.txt", effect: "deny" },
        ],
        (registry) =>
          Effect.gen(function* () {
            const denied = yield* executeTool(registry, call("write", { path: "secret.txt", content: "nope" }))
            expect(denied).toMatchObject({
              status: "error",
              error: { type: "permission.rejected", message: "Permission denied: edit" },
            })
            expect(yield* exists(path.join(tmp.path, "secret.txt"))).toBe(false)

            const allowed = yield* executeTool(
              registry,
              call("write", { path: "public.txt", content: "ok" }, "call-write-public"),
            )
            expect(allowed.status).toBe("completed")
            expect(yield* read(path.join(tmp.path, "public.txt"))).toBe("ok")
          }),
      ),
    ),
  )

  it.live("denies a write matched by an absolute deny rule", () =>
    withTempDir((tmp) =>
      run(
        tmp.path,
        [
          { action: "edit", resource: "*", effect: "allow" },
          { action: "edit", resource: path.join(tmp.path, "secret.txt"), effect: "deny" },
        ],
        (registry) =>
          Effect.gen(function* () {
            const denied = yield* executeTool(registry, call("write", { path: "secret.txt", content: "nope" }))
            expect(denied).toMatchObject({
              status: "error",
              error: { type: "permission.rejected", message: "Permission denied: edit" },
            })
            expect(yield* exists(path.join(tmp.path, "secret.txt"))).toBe(false)
          }),
      ),
    ),
  )

  it.live("denies an edit matched by a ./ deny rule and preserves the file", () =>
    withTempDir((tmp) =>
      Effect.gen(function* () {
        const secret = path.join(tmp.path, "secret.txt")
        const publicFile = path.join(tmp.path, "public.txt")
        yield* Effect.promise(() => Promise.all([fs.writeFile(secret, "before"), fs.writeFile(publicFile, "before")]))
        yield* run(
          tmp.path,
          [
            { action: "edit", resource: "*", effect: "allow" },
            { action: "edit", resource: "./secret.txt", effect: "deny" },
          ],
          (registry) =>
            Effect.gen(function* () {
              const denied = yield* executeTool(
                registry,
                call("edit", { path: "secret.txt", oldString: "before", newString: "after" }),
              )
              expect(denied).toMatchObject({
                status: "error",
                error: { type: "permission.rejected", message: "Permission denied: edit" },
              })
              expect(yield* read(secret)).toBe("before")

              const allowed = yield* executeTool(
                registry,
                call("edit", { path: "public.txt", oldString: "before", newString: "after" }, "call-edit-public"),
              )
              expect(allowed.status).toBe("completed")
              expect(yield* read(publicFile)).toBe("after")
            }),
        )
      }),
    ),
  )
})
