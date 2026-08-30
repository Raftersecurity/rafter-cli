import { Command } from "commander";
import { createSurfaceDiffCommand } from "./diff.js";

export function createSurfaceCommand(): Command {
  const surface = new Command("surface")
    .description("Attack-surface analysis");

  surface.addCommand(createSurfaceDiffCommand());

  return surface;
}
