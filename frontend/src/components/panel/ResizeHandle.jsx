import React, { useState, useEffect, useCallback } from "react";

/**
 * ResizeHandle — sleek draggable splitter for panel resizing
 * Features hover/active glow, custom cursor, and robust pointer event capture.
 */
export default function ResizeHandle({
  onResize,
  direction = "horizontal",
  title = "Drag to resize panel",
  className = "",
}) {
  const [isDragging, setIsDragging] = useState(false);

  const handlePointerDown = useCallback(
    (e) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(true);

      let prevX = e.clientX;
      let prevY = e.clientY;

      const handlePointerMove = (moveEvent) => {
        const deltaX = moveEvent.clientX - prevX;
        const deltaY = moveEvent.clientY - prevY;
        prevX = moveEvent.clientX;
        prevY = moveEvent.clientY;

        if (onResize) {
          onResize(direction === "horizontal" ? deltaX : deltaY);
        }
      };

      const handlePointerUp = () => {
        setIsDragging(false);
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
        window.removeEventListener("pointermove", handlePointerMove);
        window.removeEventListener("pointerup", handlePointerUp);
      };

      document.body.style.cursor =
        direction === "horizontal" ? "col-resize" : "row-resize";
      document.body.style.userSelect = "none";

      window.addEventListener("pointermove", handlePointerMove);
      window.addEventListener("pointerup", handlePointerUp);
    },
    [onResize, direction]
  );

  return (
    <div
      onPointerDown={handlePointerDown}
      title={title}
      className={`panel-resize-handle ${direction} ${isDragging ? "active" : ""} ${className}`}
    >
      <div className="resize-grip-line" />
    </div>
  );
}
