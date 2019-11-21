import pygame
import os
import time
import random

class pictogram:
    def __init__(self):
        self.colors=[(220, 0, 0),
                    (220,220, 0),
                    (0, 0, 220),
                    (255, 255, 255)
                    ]
        self.screen_color = (0, 0, 128)
        os.putenv('SDL_FBDEV', '/dev/fb1')
        pygame.init()
        pygame.mouse.set_visible(False)
        self.lcd = pygame.display.set_mode((480, 320))
        self.lcd.fill((0,0,0))
        pygame.display.update()
        self.fill_screen(self.screen_color)


    def fill_screen(self, color):
        self.lcd.fill(color)
        pygame.display.update()


    def draw_box(self, data):
        # Draw Yellow outline box...
        pygame.draw.rect(self.lcd, (255, 255, 0), (10, 10, 460, 300), 2)

        # Draw filled White box...
        pygame.draw.rect(self.lcd, (255, 255, 255), (100, 20, 280, 280), 0)

        # Draw 8x8 cells...
        d = bin(data)
        d = d[2:]
        for _ in range(128 - len(d)):
            d = '0' + d
        
        x = 0
        for i in range(8):
            for j in range(8):
                t = d[x] + d[x+1]
                if t == '00':
                    color = 3
                elif t == '01':
                    color = 0
                elif t == '10':
                    color = 1
                else:
                    color = 2
                pygame.draw.rect(self.lcd, self.colors[color], (112+(j*32),32+(i*32), 32, 32), 0) 
                x+=2
        
        # Draw outer grid
        pygame.draw.rect(self.lcd, (0, 0, 0), (112, 32, 256, 256), 3)
        for i in range (8):
            for j in range(8):
                pygame.draw.rect(self.lcd, (0, 0, 0), (112+(i*32), 32+(j*32), 32, 32), 2)

        pygame.display.update()
