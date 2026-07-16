import * as React from 'react'
import { cn } from '@/lib/utils'

interface SplitPaneProps {
  direction?: 'horizontal' | 'vertical'
  defaultSize?: number // px for the first pane
  minSize?: number
  maxSize?: number
  children: [React.ReactNode, React.ReactNode]
  className?: string
}

export function SplitPane({
  direction = 'horizontal',
  defaultSize = 300,
  minSize = 100,
  maxSize = 800,
  children,
  className,
}: SplitPaneProps) {
  const [size, setSize] = React.useState(defaultSize)
  const prevDefault = React.useRef(defaultSize)
  if (prevDefault.current !== defaultSize) {
    prevDefault.current = defaultSize
    // Sync state when parent changes the default (e.g. detail panel open/close)
    setSize(defaultSize)
  }
  const dragging = React.useRef(false)
  const containerRef = React.useRef<HTMLDivElement>(null)

  const isHorizontal = direction === 'horizontal'

  React.useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!dragging.current || !containerRef.current) return
      e.preventDefault()
      const rect = containerRef.current.getBoundingClientRect()
      const pos = isHorizontal ? e.clientX - rect.left : e.clientY - rect.top
      setSize(Math.min(maxSize, Math.max(minSize, pos)))
    }
    const onMouseUp = () => {
      if (dragging.current) {
        dragging.current = false
        document.body.style.userSelect = ''
        document.body.style.cursor = ''
      }
    }

    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)
    return () => {
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('mouseup', onMouseUp)
    }
  }, [isHorizontal, minSize, maxSize])

  return (
    <div
      ref={containerRef}
      className={cn(
        'flex h-full w-full overflow-hidden',
        isHorizontal ? 'flex-row' : 'flex-col',
        className,
      )}
    >
      <div
        className="shrink-0 overflow-hidden"
        style={isHorizontal ? { width: size } : { height: size }}
      >
        {children[0]}
      </div>
      <div
        className="resizable-handle group shrink-0"
        aria-orientation={isHorizontal ? 'vertical' : 'horizontal'}
        onMouseDown={() => {
          dragging.current = true
          document.body.style.userSelect = 'none'
          document.body.style.cursor = isHorizontal ? 'col-resize' : 'row-resize'
        }}
      >
        <div className="resizable-handle-grip" />
      </div>
      <div className="min-h-0 min-w-0 flex-1 overflow-hidden">
        {children[1]}
      </div>
    </div>
  )
}
