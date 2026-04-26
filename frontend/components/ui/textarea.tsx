import * as React from 'react'
import { cn } from '@/lib/utils'

export type TextareaProps = React.TextareaHTMLAttributes<HTMLTextAreaElement>

const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        'clay-input flex min-h-[120px] w-full resize-none px-3 py-2 text-sm text-[#1a1a1a] placeholder:text-[#9a9a9a]',
        className
      )}
      {...props}
    />
  )
)
Textarea.displayName = 'Textarea'

export { Textarea }
