from inky import InkyPHAT
from PIL import Image, ImageFont, ImageDraw
from time import sleep

class draw_words():
    def __init__(self):
        # Start by loading the word list
        with open('longwords.txt', 'r') as f:
            self.word_list = f.read().splitlines()

        self.d = InkyPHAT("red")
        self.d.set_border(self.d.RED)

        self.d.h_flip=True
        self.d.v_flip=True

        self.font = ImageFont.load("font.pil")
    
    def cls(self):
        img = Image.new("P", (self.d.WIDTH, self.d.HEIGHT))
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, self.d.WIDTH, self.d.HEIGHT], fill=self.d.BLACK)
        self.d.set_image(img)
        self.d.show()     

    def draw_list(self, key_code):
        img = Image.new("P", (self.d.WIDTH, self.d.HEIGHT))
        draw = ImageDraw.Draw(img)
        
        # Start by filling the screen with a black fill...
        draw.rectangle([0, 0, self.d.WIDTH, self.d.HEIGHT], fill=self.d.BLACK)
        
        int_value = int(key_code, 16)
        bits_list=[]
        mask = 0x1FFF

        for i in range(9):
            bits_list.append((int_value >> (13 * i)) & mask)

        bits_list.append(int_value >> 117)

        # Now we have the word list - we need to pad the final block to 13-bits...
        bits_list[9] = bits_list[9] << 2

        words=[]
        for block in bits_list:
            words.append(self.word_list[block])

        i = 0
        l_col = True
        for word in words:
            y = (22 * (i + 1)) - 3 #2
            draw.line((0, y, self.d.WIDTH, y), self.d.RED, 2)
            if l_col:
                draw.text((5, (i * 22) - 2), word.upper(), self.d.WHITE, self.font)
            else:
                draw.text((110, (i * 22) - 2), word.upper(), self.d.WHITE, self.font)
                i += 1

            l_col = not(l_col)

        draw.line((0, 0, 0, self.d.HEIGHT), self.d.RED, 2)
        draw.line((self.d.WIDTH / 2, 0, self.d.WIDTH / 2, self.d.HEIGHT), self.d.RED, 2)
        draw.line((self.d.WIDTH - 2, 0, self.d.WIDTH - 2, self.d.HEIGHT), self.d.RED, 2)

        self.d.set_image(img)
        self.d.show()

