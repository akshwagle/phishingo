'use client'

import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'clay-btn inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm disabled:opacity-45',
  {
    variants: {
      variant: {
        default: 'bg-[#4f46e5] text-white',
        outline: 'bg-[#fffefb] text-[#1a1a1a]',
        subtle:  'bg-[#ffe9a0] text-[#1a1a1a]',
        danger:  'bg-[#ffb3b3] text-[#1a1a1a]',
        success: 'bg-[#b3f0c8] text-[#1a1a1a]',
        ghost:   'bg-transparent border-transparent shadow-none text-[#1a1a1a] hover:bg-[#f5f0e8]',
      },
      size: {
        default: 'h-11 px-5 py-2',
        sm:      'h-9  px-4 py-1.5 text-xs',
        lg:      'h-13 px-7 py-3 text-base',
        icon:    'h-10 w-10',
      },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  }
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  )
)
Button.displayName = 'Button'

export { Button, buttonVariants }
