# heldfast

Launcher for [heldfast](https://github.com/rufat325/heldfast), which pins the
tool definitions an MCP server showed you and refuses tools that change after
you approved them.

The tool itself is a Python package:

    pipx install heldfast

Once it is installed, `npx heldfast <command>` runs it -- `npx heldfast -- <server>`
is `heldfast wrap -- <server>`. This package downloads nothing on its own; it finds
the installed tool and runs it. The same launcher is published as
`@rufat325/heldfast`.
