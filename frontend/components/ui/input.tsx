import * as React from 'react'
import { cn } from '@/lib/utils'

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => (
    <input
      type={type}
      ref={ref}
      className={cn(
        'clay-input flex h-11 w-full px-3 py-2 text-sm text-[#1a1a1a] placeholder:text-[#9a9a9a]',
        className
      )}
      {...props}
    />
  )
)
Input.displayName = 'Input'

export { Input }
