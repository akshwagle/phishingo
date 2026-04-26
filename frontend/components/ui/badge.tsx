import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'clay-badge inline-flex items-center px-2.5 py-0.5 text-xs font-bold',
  {
    variants: {
      variant: {
        default: 'bg-[#b3c8ff] text-[#1a1a1a]',
        success: 'bg-[#b3f0c8] text-[#1a1a1a]',
        warning: 'bg-[#ffe9a0] text-[#1a1a1a]',
        danger:  'bg-[#ffb3b3] text-[#1a1a1a]',
        outline: 'bg-[#fffefb] text-[#1a1a1a]',
        purple:  'bg-[#d4b3ff] text-[#1a1a1a]',
      },
    },
    defaultVariants: { variant: 'default' },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants }
