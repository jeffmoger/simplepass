import simple

if __name__ == '__main__':
    if simple.get_version():
        simple.main()
    else:
        print('You need to be on Python 3.0 or greater to run SimplePass.')
