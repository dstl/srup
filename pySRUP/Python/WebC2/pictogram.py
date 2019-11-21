from PIL import Image


class Monochrome:
    def __init__(self, pixel_width):
        self.__pixel_width = pixel_width

        # Now some "constants" – based on how the 12x12 monochrome picotgram is defined...
        self.__cell_count = 12      # Always 12x12 cells in the monochrome pictogram
        self.__max_grid = 127       # Spec is for 0-127 bits, with 4x (2x2) corner blocks...
        self.__corner_offset = 2    # Corner block size is 2x2 cells...

        # Next some calculations based on the constants – to show working...
        # Cell Size is the size of each of the cells – as 1/12 of the total size...
        self.__cell_size = self.__pixel_width // self.__cell_count

        # Narrow Width is the width in cells of the top & bottom rows where the fixed corners take up space...
        self.__narrow_width = self.__cell_count - (2 * self.__corner_offset)

        # Narrow Count is the number of cells in each of the top & bottom narrow sections...
        self.__narrow_count = self.__corner_offset * self.__narrow_width

        # Narrow Base is the row in which the bottom narrow section starts
        self.__narrow_base = self.__cell_count - self.__corner_offset

        # Lastly the actual PIL image data...
        self.__image = Image.new('1', (pixel_width, pixel_width), 1)
        self.__pixels = self.__image.load()

    def __plot_cell(self, x, y):
        # Plot black cells ...
        for px in range(self.__cell_size):
            for py in range(self.__cell_size):
                self.__pixels[(x * self.__cell_size) + px, (y * self.__cell_size) + py] = 0

    def __init_corners(self):
        # Next we'll use the above, to initialize the corners with a 2x2 black cell (as per the spec)...
        n = [0, 0 + 1, self.__cell_count - 2, self.__cell_count - 1]
        for px in range(4):
            for py in range(4):
                    self.__plot_cell(n[px], n[py])

    def __map_to_grid(self, digit):
        x, y = 0, 0

        if self.__narrow_count <= digit <= (self.__max_grid - self.__narrow_count):
            x = (digit - self.__narrow_count) % self.__cell_count
            y = ((digit - self.__narrow_count) // self.__cell_count) + self.__corner_offset

        elif digit < self.__narrow_count:
            x = (digit % self.__narrow_width) + self.__corner_offset
            y = digit // self.__narrow_width

        elif digit >= (self.__max_grid - self.__narrow_count):
            dd = digit - (self.__max_grid - (self.__narrow_count - 1))
            x = (dd % self.__narrow_width) + self.__corner_offset
            y = (dd // self.__narrow_width) + self.__narrow_base

        # For debug – print the co-ordinates...
        # print("Digit={}, x={}, y={}".format(digit, x, y))

        return [x, y]

    def plot_uuid(self, uuid):
        self.__init_corners()

        d = bin(uuid)

        d = d[2:]

        icount = 0
        for i in d:
            if i == '1':
                tx, ty = self.__map_to_grid(icount)
                self.__plot_cell(tx, ty)
            icount += 1

        return self.__image


class Color:
    def __init__(self, pixel_width):
        self.__pixel_width = pixel_width

        # Now some "constants" – based on how the 8x8 color picotgram is defined...
        self.__cell_count = 8      # Always 8x8 cells in the monochrome pictogram

        # Next some calculations based on the constants – to show working...
        # Cell Size is the size of each of the cells – as 1/12 of the total size...
        self.__cell_size = self.__pixel_width // self.__cell_count

        # Lastly the actual PIL image data...
        self.__image = Image.new('RGB', (pixel_width, pixel_width), (255, 255, 255))
        self.__pixels = self.__image.load()

    def __plot_cell(self, x, y, color):
        # Plot black cells ...
        for px in range(self.__cell_size):
            for py in range(self.__cell_size):
                self.__pixels[(x * self.__cell_size) + px, (y * self.__cell_size) + py] = color

    def __map_to_grid(self, digit):
        x = digit % self.__cell_count
        y = digit // self.__cell_count
        return [x, y]

    def __draw_grid(self):
        for count in range(self.__cell_count):
            for xy in range(self.__pixel_width):
                self.__pixels[xy, count * self.__cell_size] = (0, 0, 0)
                self.__pixels[count * self.__cell_size, xy] = (0, 0, 0)
                if count == 0:
                    self.__pixels[self.__pixel_width - 1, xy] = (0, 0, 0)
                    self.__pixels[xy, self.__pixel_width - 1] = (0, 0, 0)

    def plot_uuid(self, uuid):
        d = bin(uuid)
        d = d[2:]

        for pre_pad in range(128 - len(d)):
            d = '0' + d

        count = 0
        for i in range(0, 127, 2):
            t = d[i] + d[i+1]
            if t == '00':
                color = (255, 255, 255)
            elif t == '01':
                color = (255, 0, 0)
            elif t == '10':
                color = (255, 255, 0)
            else:
                color = (0, 0, 255)

            tx, ty = self.__map_to_grid(count)
            self.__plot_cell(tx, ty, color)
            count += 1

        self.__draw_grid()
        return self.__image
